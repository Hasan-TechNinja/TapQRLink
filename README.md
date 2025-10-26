# TapQRLink

Local payment time should start the server: 

    1. Stripe login: stripe login
    2. Stripe CLI : stripe listen --forward-to localhost:8001/webhooks/stripe/

System dependency (ubuntu):  
    1. sudo apt-get install libzbar0


``
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.ionos.com'
EMAIL_PORT = 587  # TLS
EMAIL_USE_TLS = True  # TLS use korben
EMAIL_USE_SSL = False  # SSL false thakbe jodi TLS use koren
EMAIL_HOST_USER = 'help@tapqrlink.com'
EMAIL_HOST_PASSWORD = 'Uniquecode1$$'  # IONOS email password
DEFAULT_FROM_EMAIL = 'noreply@tapqrlink.com'