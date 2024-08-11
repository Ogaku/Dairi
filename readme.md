# Dairi

**Dairi** is a web service (that you take care of) that acts as a CORS-bypass proxy thingie for Oshi web app.  
It allows the app to make cross-origin requests without being blocked by the browser's same-origin policy.

## Setup Instructions

To set up Dairi with render.com, follow these steps:

1. Sign up for an account on [render.com](https://render.com) if you haven't already.

2. Create a new web service on render.com and choose 'Public Git Repository'  
[[IMAGE]]

3. Set upp all properties as shown in the image below, select the 'Free' tier  
[[IMAGE]]

4. Click 'Deploy Web Service' and grab the URL of the service once it's deployed  
[[IMAGE]]

5. In the Oshi web app, update the proxy endpoint to use the URL of your service.

6. Do some testing to ensure that you can now make cross-origin requests.

That's it! You've successfully set up a CORS-bypass proxy for Oshi web using render.com.
