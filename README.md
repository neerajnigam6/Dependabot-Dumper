* Dependabot dumper

This script dumps all issues created by dependabot on local folder.

*** How to use:

Modify "config.py" file, put value of github access token and repository for which you want to run the script and let it do its job.
Add variable ACCOUNT_NAME such as -> account_name/repo_name 

*** How to generate github access token?
Go to github.com > settings > Developer Settings > Personal access token.

__don't forget to authorize with SSO in case you are accessing organization account.__

*** Troubleshooting
1. Check githib token is valid
2. Check github token has SSO access, in case of Organization repo
3. Check User has Dependabot issue access
4. Check typos etc.

