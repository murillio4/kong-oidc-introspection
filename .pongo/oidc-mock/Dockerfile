FROM node:14.15-alpine

RUN apk add --no-cache curl bash

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 8080

CMD [ "node", "index.js" ]