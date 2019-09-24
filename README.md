# Item Cataloge Project
This is second project in udacity fullstack nanodegree

## Start project instructions
follow this instruction to be able to run the project
### Install virual env
```bash
sudo pip3 install virtualenv
```
### Creat virual env
```bash
virtualenv venv
```
### Active your virtual environment
```bash
source venv/bin/activate
```
### Install project requirments
```bash
pip install -r requirements.txt
```
### Run database setup
```bash
python3 database_setup.py
```
### Google auth
Add client_secret.json create auth2 credintial from google console download your client_secret.json and
put file in project folder beside app.py or create it and fill with your credentials
```json
{
    "web": {
        "client_id": "YOUR CLIENT ID",
        "client_secret": "YOUR SECRET ID",
        "project_id": "YOUR_PROJECT_ID",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "redirect_uris": [
            "http://localhost:5000"
        ],
        "javascript_origins": [
            "http://localhost:5000"
        ]
    }
}
```
### Create env.json
create it and fill with your app secret key 
dont forget to replace `APP_SECRET_KEY` with strong hash 

```json
{
    "appSecreteKey":"APP_SECRET_KEY"
}
```

### Run the project 
```bash 
python3 app.py 
```