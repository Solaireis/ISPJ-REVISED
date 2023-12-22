# Stage 1: Install node.js and build the tailwindcss and minify the css and js files
FROM node:19 as node

# Copy local code to the container image
ENV APP_HOME /mirai
COPY / $APP_HOME
WORKDIR $APP_HOME

# install nodejs
RUN npm install
RUN npx browserify -p esmify ./src/app/static/js/modules.js > ./src/app/static/js/bundles.js
RUN npm run minify-css
RUN rm -f ./src/app/static/css/main.css

RUN npm install -g uglify-js
# Run UglifyJS to minify all the JavaScript files in the directory
RUN find ./src/app/static/js -name "*.js" -exec sh -c 'uglifyjs "${0}" -c -m -o "${0%.*}.js"' {} \;

RUN npm install -g clean-css-cli
# Run CleanCSS to minify all the CSS files in the directory except the tailwind.css file
RUN find ./src/app/static/css -name "*.css" -not -name "tailwind.css" -exec sh -c 'cleancss -o "${0%.*}.css" "${0}"' {} \;

# Final Stage: Install python and install the dependencies and run the FastAPI app
FROM python:3.11.2-slim

# Allow statements and log messages to immediately appear in the Knative logs
ENV PYTHONUNBUFFERED True

ENV APP_HOME /mirai
COPY --from=node $APP_HOME $APP_HOME
WORKDIR $APP_HOME

# # Install the dependencies
RUN pip install -U pip
RUN pip install -U hypercorn
RUN cat requirements.txt | grep -v "uvicorn\[standard\]" > requirements_without_uvicorn.txt
RUN pip install -r requirements_without_uvicorn.txt

# RUN python3 download_dependencies.py

# Remove the python script and the requirements file
# after the dependencies are installed
RUN rm -f requirements.txt requirements_without_uvicorn.txt

# Set PORT env for FastAPI app to Listen on port 8080
ENV PORT 8080

# Run the web service on container startup using uvicorn
# <filename>:<app variable name>
WORKDIR $APP_HOME/src/app
CMD exec hypercorn --bind 0.0.0.0:$PORT --workers 4 main:app