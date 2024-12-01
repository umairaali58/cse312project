# Recipe App

A simple web application for sharing and liking recipes, built with Flask and Dockerized for easy deployment.

## Table of Contents

1. [Features](#features)
2. [Installation](#installation)
3. [Usage](#usage)

## Features

- **Recipe Posting**: Users can submit new recipes including a title, ingredients, and an image.
- **Image Storage**: Recipes are accompanied by images stored in a designated directory.
- **User Interaction**: Users can like recipes.
- **Dynamic Display**: Recipes are displayed dynamically with images and essential details.

## Installation

To set up the project using Docker Compose, follow these steps:

1. **Clone the repository**:
   ```bash
   git clone <git@github.com:umairaali58/cse312project.git>
   cd cse312project
   ```

2. **Dependencies**:
   Take a look at `requirements.txt` for a detailed list of dependencies used in the project.

3. **Run the application using Docker Compose**:
   ```bash
   docker-compose up
   ```

   This command will build the Docker image if it is not already built and start up the application along with any necessary services.

4. **Access the application**: Open your browser and go to `http://localhost:8080`.

## Usage

- **Access Home**: Navigate through the homepage to explore the recipe options.
- **Submit Recipes**: Use the form on the recipes page to add your own recipes.
- **Like Recipes**: Click the 'Like' button to endorse recipes you enjoy.

## Docker Compose Configuration

Ensure you have a `docker-compose.yml` file in your project root, similar to the one in this project

NOTE: when deploying, remove the port mapping for db "27017:27017"
This setup will manage multiple containers (e.g., Flask and MongoDB) seamlessly and ensure your application is readily accessible.
