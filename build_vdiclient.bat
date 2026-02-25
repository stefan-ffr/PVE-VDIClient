@echo off
pyinstaller --noconsole --noconfirm --hidden-import proxmoxer.backends --hidden-import proxmoxer.backends.https --hidden-import proxmoxer.backends.https.AuthenticationError --hidden-import proxmoxer.core --hidden-import proxmoxer.core.ResourceException --hidden-import subprocess.TimeoutExpired --hidden-import subprocess.CalledProcessError --hidden-import requests.exceptions --hidden-import requests.exceptions.ReadTimeout --hidden-import requests.exceptions.ConnectTimeout --hidden-import requests.exceptions.ConnectionError --hidden-import flask --hidden-import jinja2 --add-data "templates;templates" --add-data "static;static" --noupx -i vdiicon.ico vdiclient.py
copy vdiclient.png dist\vdiclient
copy vdiicon.ico dist\vdiclient
xcopy /E /I templates dist\vdiclient\templates
xcopy /E /I static dist\vdiclient\static
cd dist
python createmsi.py vdiclient.json
cd ..
