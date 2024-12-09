# Recipe App

[recipehub.me](http://recipehub.me)

A simple web application for sharing and liking recipes, built with Flask and Docker while deployed with Nginx.

## Table of Contents

1. [Features](#features)
2. [Usage](#usage)
3. [Testing Procedures](#testing-procedures)

## Features

- **Recipe Posting**: Users can submit new recipes including a title, ingredients, and an image.
- **Image Storage**: Recipes are accompanied by images stored in a designated directory.
- **User Interaction**: Users can like recipes.
- **Dynamic Display**: Recipes are displayed dynamically with images and essential details.
- **Authenticated Users List**: Displays a list of authenticated users currently active on the platform as well as the top 5 oldest users.
- **Recipe Download**: Users have the option to download recipe details for offline access.

## Usage

- **Access Home**: Visit our newly deployed site at [recipehub.me](http://recipehub.me) to explore the recipe options.
- **Submit Recipes**: Easily upload your recipes along with images directly from the recipe page.
- **Create an Account**: Sign up from the home page to start sharing and liking recipes.
- **Like Recipes**: Click the 'Like' button to endorse recipes you enjoy.
- **Download Recipes**: Use the "Download" button to save a copy of the recipe details to your device.

## Testing Procedures

### Testing the Download Recipe Feature

1. **Access the Platform**: go to recipehub.me to test this feature (you can log in via home or stay as guest, it doesn't matter).
2. **Navigate to Recipes**: Go to the Recipes section where all recipes are displayed.
3. **Locate Download Button**: Each recipe card should have a "Download" button.
    - if there are no recipes, feel free to make one (must include image with post).
    - you can format the ingredient list as you please (with or without commas, the download will account for both)
4. **Download Process**:
   - Click the "Download" button on a recipe you wish to download.
   - Verify that a download action is triggered.
   - Ensure that the recipe details are downloaded successfully as a pdf file.
5. **Verify File Contents**:
   - Open the downloaded pdf file on your device.
   - Ensure the file includes the correct recipe details such as title, ingredients, username, and image as the post.
