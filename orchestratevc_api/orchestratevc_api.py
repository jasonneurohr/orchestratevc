from eve import Eve


app = Eve(settings='settings.py')
app.run(port=5000, host='0.0.0.0')