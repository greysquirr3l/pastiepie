#!/bin/bash

# Define required variables
REQUIRED_VARS=("MASTER_KEY" "DB_PATH" "LOG_LEVEL" "PORT")

# Paths
ENV_FILE="/root/.env"
CONFIG_FILE="/root/config.yml"

# Create the .env file
echo "# Temporary Environment Variables" > $ENV_FILE

echo "Checking required environment variables..."
for VAR in "${REQUIRED_VARS[@]}"; do
  VALUE=$(printenv $VAR) # Get the variable's value
  if [ -z "$VALUE" ]; then
    echo "Error: $VAR is not set. Exiting."
    exit 1
  fi
  echo "$VAR=$VALUE" >> $ENV_FILE
done

# Debugging output
echo "DB_PATH value: $(printenv DB_PATH)"

# Write values to config.yml
echo "Writing variables to $CONFIG_FILE..."
cat <<EOL > $CONFIG_FILE
log_level: "$(printenv LOG_LEVEL)"
aes_key: "$(printenv MASTER_KEY)"
db_path: "$(printenv DB_PATH)"
port: "$(printenv PORT)"
EOL

# Validate config.yml
if ! grep -q "db_path: " $CONFIG_FILE; then
  echo "Error: db_path is missing or empty in $CONFIG_FILE."
  exit 1
fi

# Clear the .env file for security
echo "Clearing temporary .env file..."
rm -f $ENV_FILE

if [ $? -ne 0 ]; then
  echo "Warning: Failed to delete temporary .env file. Please remove it manually."
else
  echo "Temporary .env file cleared."
fi

echo "Environment variables successfully written to $CONFIG_FILE."
