/*
   Unix SMB/CIFS implementation.
   Authentication token refresh utilities
   Copyright (C) 2024

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "auth.h"
#include "passdb.h"
#include "passdb/lookup_sid.h"
#include "../libcli/security/security.h"
#include "lib/util_sid_passdb.h"
#include "lib/util/debug.h"
#include "lib/param/loadparm.h"
#include "idmap_cache.h"
#include "idmap.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

/**
 * Compare two security tokens to see if group membership has changed
 */
static bool tokens_differ(const struct security_token *old_token,
			  const struct security_token *new_token)
{
	uint32_t i, j;
	
	if (old_token->num_sids != new_token->num_sids) {
		return true;
	}
	
	/* Check if all SIDs in old token exist in new token */
	for (i = 0; i < old_token->num_sids; i++) {
		bool found = false;
		for (j = 0; j < new_token->num_sids; j++) {
			if (dom_sid_equal(&old_token->sids[i], &new_token->sids[j])) {
				found = true;
				break;
			}
		}
		if (!found) {
			return true;
		}
	}
	
	return false;
}

/**
 * Update unix token (uid/gid/groups) from security token
 * Reuses logic from create_local_nt_token functions
 */
static NTSTATUS update_unix_token_from_security_token(
	struct auth_session_info *session_info,
	const struct security_token *new_security_token)
{
	NTSTATUS status;
	uint32_t i;
	gid_t *new_groups = NULL;
	uint32_t num_groups = 0;
	TALLOC_CTX *tmp_ctx;
	struct unixid *ids = NULL;
	
	if (!session_info->unix_token) {
		DEBUG(3, ("No unix token to update\n"));
		return NT_STATUS_OK;
	}
	
	tmp_ctx = talloc_new(NULL);
	if (!tmp_ctx) {
		return NT_STATUS_NO_MEMORY;
	}
	
	/* Convert SIDs to unix IDs */
	ids = talloc_array(tmp_ctx, struct unixid, new_security_token->num_sids);
	if (!ids) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	
	if (!sids_to_unixids(new_security_token->sids, new_security_token->num_sids, ids)) {
		DEBUG(1, ("Failed to convert SIDs to unix IDs\n"));
		status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}
	
	/* Count valid group IDs and create new groups array */
	for (i = 0; i < new_security_token->num_sids; i++) {
		if (ids[i].type == ID_TYPE_GID || ids[i].type == ID_TYPE_BOTH) {
			/* Skip the primary user SID (first SID) */
			if (i > 0) {
				num_groups++;
			}
		}
	}
	
	if (num_groups > 0) {
		new_groups = talloc_array(tmp_ctx, gid_t, num_groups);
		if (!new_groups) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}
		
		num_groups = 0; /* Reset counter */
		for (i = 0; i < new_security_token->num_sids; i++) {
			if (ids[i].type == ID_TYPE_GID || ids[i].type == ID_TYPE_BOTH) {
				/* Skip the primary user SID (first SID) */
				if (i > 0) {
					new_groups[num_groups] = (gid_t)ids[i].id;
					num_groups++;
				}
			}
		}
	}
	
	/* Update unix token */
	TALLOC_FREE(session_info->unix_token->groups);
	session_info->unix_token->groups = NULL;
	session_info->unix_token->ngroups = 0;
	
	if (num_groups > 0) {
		session_info->unix_token->groups = talloc_move(session_info->unix_token,
							       &new_groups);
		session_info->unix_token->ngroups = num_groups;
	}
	
	DEBUG(5, ("Updated unix token with %u groups\n", num_groups));
	
	status = NT_STATUS_OK;
	
done:
	TALLOC_FREE(tmp_ctx);
	return status;
}

/**
 * Refresh user's security token by re-enumerating group memberships
 */
static NTSTATUS refresh_session_token(struct auth_session_info *session_info)
{
	NTSTATUS status;
	struct security_token *new_token = NULL;
	const struct dom_sid *user_sid;
	const char *username = NULL;
	uid_t uid;
	gid_t gid;
	char *found_username = NULL;
	bool is_guest = false;
	struct dom_sid_buf buf;
	
	if (!session_info || !session_info->security_token) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	/* Check if we have at least one SID in the security token */
	if (session_info->security_token->num_sids == 0) {
		DEBUG(1, ("refresh_session_token: No SIDs in security token\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	user_sid = &session_info->security_token->sids[0];
	
	DEBUG(5, ("Refreshing token for user SID %s\n", 
		  dom_sid_str_buf(user_sid, &buf)));
	
	/* Check if this is a guest session */
	is_guest = security_token_has_builtin_guests(session_info->security_token);
	
	/* Try to get username from session info */
	if (session_info->unix_info && session_info->unix_info->unix_name) {
		username = session_info->unix_info->unix_name;
	} else if (session_info->info && session_info->info->account_name) {
		username = session_info->info->account_name;
	}
	
	/* Use username-based token creation method */
	if (username && *username) {
		status = create_token_from_username(session_info,
						    username,
						    is_guest,
						    &uid, &gid,
						    &found_username,
						    &new_token);
	} else {
		/* No username available - we can't refresh without it */
		DEBUG(3, ("No username available for token refresh\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to refresh token for user %s: %s\n",
			  username ? username : dom_sid_str_buf(user_sid, &buf),
			  nt_errstr(status)));
		return status;
	}
	
	/* Check if token actually changed */
	if (!tokens_differ(session_info->security_token, new_token)) {
		DEBUG(10, ("Token unchanged for user %s\n",
			   username ? username : dom_sid_str_buf(user_sid, &buf)));
		TALLOC_FREE(new_token);
		goto update_timestamp;
	}
	
	DEBUG(5, ("Token changed for user %s, updating session\n",
		  username ? username : dom_sid_str_buf(user_sid, &buf)));
	
	/* Debug old vs new token */
	DEBUG(10, ("Old token:\n"));
	security_token_debug(DBGC_AUTH, 10, session_info->security_token);
	DEBUG(10, ("New token:\n"));
	security_token_debug(DBGC_AUTH, 10, new_token);
	
	/* Replace security token */
	TALLOC_FREE(session_info->security_token);
	session_info->security_token = talloc_steal(session_info, new_token);
	
	/* Update unix token to match new security token */
	status = update_unix_token_from_security_token(session_info, new_token);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to update unix token: %s\n", nt_errstr(status)));
		/* Continue with old unix token rather than failing completely */
	}
	
update_timestamp:
	/* Update timestamp regardless of whether token changed */
	session_info->token_last_update = time(NULL);
	
	return NT_STATUS_OK;
}

/**
 * Check if token needs refresh and perform it if necessary
 * This is the main entry point called from change_to_user_impersonate()
 */
void maybe_refresh_session_token(struct auth_session_info *session_info)
{
	time_t cache_time;
	time_t now;
	NTSTATUS status;
	
	if (!session_info) {
		return;
	}
	
	/* Only refresh for NTLM authentication, not Kerberos */
	if (session_info->ticket_type != TICKET_TYPE_UNKNOWN && 
	    session_info->ticket_type != TICKET_TYPE_NON_TGT) {
		/* This is likely a Kerberos ticket, don't refresh */
		return;
	}
	
	/* Check if winbind cache time is configured */
	cache_time = lp_winbind_cache_time();
	if (cache_time == 0) {
		/* Cache disabled - never refresh */
		return;
	}
	
	now = time(NULL);
	
	/* Initialize token_last_update if it's zero (first time) */
	if (session_info->token_last_update == 0) {
		session_info->token_last_update = now;
		return;
	}
	
	/* Check if refresh is needed */
	if (now - session_info->token_last_update < cache_time) {
		/* Token is still fresh */
		return;
	}
	
	DEBUG(5, ("Token refresh needed (age: %ld seconds, cache time: %ld)\n",
		  (long)(now - session_info->token_last_update),
		  (long)cache_time));
	
	/* Perform the refresh */
	status = refresh_session_token(session_info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Token refresh failed: %s\n", nt_errstr(status)));
		/* Update timestamp anyway to avoid hammering on every request */
		session_info->token_last_update = now;
	}
} 