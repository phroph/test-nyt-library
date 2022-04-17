FROM nytimes/library

# copy custom files to library's custom repo
COPY . ./custom/

# move to a temporary folder install custom npm packages
WORKDIR /usr/src/tmp
COPY package*.json .npmrc ./
RUN npm i
# copy node modules required by custom node modules
RUN yes | cp -rf ./node_modules/* /usr/src/app/node_modules

# return to app directory and build
WORKDIR /usr/src/app
RUN npm run build

# start app
CMD [ "npm", "start" ]
