FROM node:18.16.0-alpine3.17 as builder

# Set the working directory in the container
WORKDIR /usr/src/app

COPY package.json .

# Install the application dependencies
RUN npm install --omit=dev --production && \
    apk add nano curl

# Copy the application files into the working directory
COPY . .

FROM node:18.16.0-alpine3.17

WORKDIR /usr/src/app

COPY --from=builder /usr/src/app .

EXPOSE 3000

# Define the entry point for the container
CMD ["npm", "start"]