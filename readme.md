# Dairi

**Dairi** is a web service (that you take care of) that acts as a CORS-bypass proxy thingie for Oshi web app.  
It allows the app to make cross-origin requests without being blocked by the browser's same-origin policy.

## Setup Instructions

To set up Dairi with render.com, follow these steps:

1. Sign up for an account on [render.com](https://render.com) if you haven't already  

2. Create a new web service on render.com and choose 'Public Git Repository'  
![Screenshot](https://github.com/user-attachments/assets/f0dbc2fa-bbb8-4b05-9565-0c88900d7463)

3. Paste Dairi's link under the 'Public Git Repository' field  
![Screenshot](https://github.com/user-attachments/assets/0cb0d139-56a5-4b0a-b0bb-26efed91a13a)

4. Set upp all properties as shown in the image below, and choose your own service name  
![Screenshot](https://github.com/user-attachments/assets/40d5b8e4-199d-4409-822a-32ce9cc3d71d)

5. Select the 'Free' tier for 750h of uptime each month, which is just about enough for us (31.25 days)  
![Screenshot](https://github.com/user-attachments/assets/5b456ab7-7ea0-4322-8853-90557b8568f5)

6. Click 'Deploy Web Service' and grab the URL of the service once it's deployed  
![Screenshot](https://github.com/user-attachments/assets/c39c9324-e476-4d0d-95c9-563de7eedae5)  
![Screenshot](https://github.com/user-attachments/assets/140ce7cf-8bfd-4fff-adbf-72a1d65ff41b)

7. In the Oshi web app, paste the proxy endpoint address to use your new service
![image](https://github.com/user-attachments/assets/4808c6d3-57ae-4243-8c0d-b14f77612eed)

8. Do some testing to ensure that you can now make cross-origin requests

### That's it! You've successfully set up a CORS-bypass proxy for Oshi web using render.com
