# About this project
This project (made in golang) was created for the endpointer event at [hackclub](https://endpointer.hackclub.com/)
The project is called CodeBin and is like pastebin but instead an api version and also targeted for coding. 
You can use this api to store your coding snippets and also search other snippets by coding language.
The project also supports JWT auth meaning it is possible to have accounts which are linked to your email (When signing up you'll get an email with a code to verify your account)
For reasons you probably understand. You can only make 20 requests per minute and there is also a 50kb storage limit per user. 

## Here are the different endpoints you can try out: 

### /about
Get infomation about your account
### /create
Create snippets
### /delete
Delete snippets you've made
### /edit/{id}
edit your snippet by providing the snippet id
### /sl/{lang}
search snippets based of the programming language
### /view/{id}
view a snippet from its id
### /request-token
Request a token to verify your account
### /verify-token
Verify your account by submitting your email and the token sent to you

## How to self host

# 0. Install golang
different for each operating system but is very straightforward

# 1. Git clone the project
```git clone https://github.com/ItsHotdogFred/CodeBin.git```
# 2. Create an env file
Create an env file in the Codebin root
# 3. Fill the .env file
To get the project working you need to add the following 3 things:
JWT_SECRET (This can be equal to anything but is best to use a password over 30 characters with a mix of letters, numbers and symbols)
MAILTRAP_API_TOKEN (Sign up for mailtrap [here](https://mailtrap.io/) and choose the free plan and then follow the guide on getting api/smtp setup which will give you your api key)
MAILTRAP_EMAIL (The email you'll be using to send verification codes to people)
# 4. Run the project
While in the project root, run ```go run .``` which will start the project. The db will be automatically created 
