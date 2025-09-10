# TapQRLink

Local payment time should start the server: 

    1. Stripe login: stripe login
    2. Stripe CLI : stripe listen --forward-to localhost:8001/webhooks/stripe/

System dependency (ubuntu):  
    1. sudo apt-get install libzbar0
