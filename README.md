# External Accounts Connector

Enables users to connect external accounts into CSH LDAP

Link with `GET /<service_name>`
Revoke with `DELETE /<service_name`

Currently supported services:
 * Slack - Records Slack ID for use by bots and other applications.
 * Github - Records GitHub username and handles membership in organisation.
 * Twitch - Records Twitch username for sharing and use by bots

### Adding a new External service
 1. Add routes. Every service requires a DELETE and a GET route, for revoking and granting authorization respectively. 
 2. Add the service to the services dictionary in \_index
 3. Add a logo for the service in eac/static/logos/
 4. Test your changes locally to make sure the flow is correct.

For CSH ldap, you will also need to have write access added to the member fields EAC administers. Please reach out to an RTP to do that. We also encourage for any service added to EAC, a corresponding change be made to prevent modifying that value from [profiles](https://github.com/ComputerScienceHouse/profiles).

### Running locally
Configuration is handled by environment variables. [config.env.py](./config.env.py) will pull variables from the environment and pass them to the application. If you want to write secrets to a file, EAC supports a `config.py` file. This file is a clone of config.env.py, but with secrets instead of environ.get statements. This file will be ignored by git.

If you add configuration secrets, you will need to add them to config.env.py so they may be configured in the production environment.

Once you have secrets configured, the following will get the application running. Command aliases may differ on your system. EAC requires Python 3 [(install steps)](https://docs.python-guide.org/starting/installation/) and pip, and we recommend virtualenv as well.

 ```
# Install dependencies. We recommend using a virtual environment
## Optional - keeps your system cleaner
python3 -m virtualenv venv
source venv/bin/activate
## End Optional
pip3 install -r requirements.txt

flask run -h localhost -p 5000
 ```

### Linting
 ```
# Install types
mypy --install-types

# Check linting
mypy app.py config.env.py eac
# Check Typing
pylint app.py config.env.py eac
# Format
yapf -ir app.py config.env.py eac
 ```
