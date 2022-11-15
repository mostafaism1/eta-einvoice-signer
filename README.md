# ETA E-Invoice Signer

## Description

- A web application for signing documents in accordance with the [algorithm](https://sdk.invoicing.eta.gov.eg/signature-creation) described by the Egyptian Tax Authority (ETA).

## Installation

### Requirements

- JDK 17
  - Oracle JDK 17 can be downloaded from [here](https://www.oracle.com/java/technologies/javase/jdk17-archive-downloads.html).

### Building

- Clone the repository to your local environment:

  ```console
  $git clone https://github.com/mostafaism1/eta-einvoice-signer
  ```

  ```console
  $cd eta-einvoice-signer
  ```

- Build the project:

  - Linux/MacOS:

    ```console
    $./mvnw clean package
    ```

  - Windows:

    ```console
    $.\mvnw.cmd clean package
    ```

- The previous step should output a .jar file in the target directory.

### Configuration

- See `src/main/resources/application.properties` for all available configuration properties.
- Create a [.properties](https://en.wikipedia.org/wiki/.properties) file containing all properties to override.
- [Run](#running) the application with the `-DconfigFilePath` JVM argument and set it to the path of the configuration file created in the previous step.

#### Server Port

- Set `server.port` to the desired port.

#### SSL

- To enable SSL, set `server.ssl.enabled` to `true` and set the following properties:

  - `server.ssl.key-store-type`
  - `server.ssl.key-store`
  - `server.ssl.key-store-password`
  - `server.ssl.key-alias`

#### Signature Keystore

- The application supports 2 types of keystores for signature creation:
  - Hardware token keystore
  - File-based keystore

##### Hardware Token Keystore

- Set `signature.keystore.type` to `hardware`, and set the following properties:
  - `signature.keystore.pkcs11ConfigFilePath`
  - `signature.keystore.password`
  - `signature.keystore.certificateIssuerName`

##### File-based Keystore

- Set `signature.keystore.type` to `file`, and set the following properties:
  - `signature.keystore.pkcs12KeyStoreFilePath`
  - `signature.keystore.password`
  - `signature.keystore.certificateIssuerName`

#### Authentication

- The application uses HTTP Basic authentication.
- Only 1 user can be defined.
- To configure the user's details:
  - Set `auth.user.userName` to the user name.
  - Set `auth.user.encryptedPassword` to the bcrypt hash of the password.
    - There are many tools to generate a bcrypt hash. Here's [one](https://bcrypt.online/) such tool.

### Running

- Run the .jar from the build step:

  ```console
  $java [-DconfigFilePath=CONFIGURATION_FILEPATH] -jar eta-einvoice-signer-1.0-SNAPSHOT.jar
  ```

## Usage

### Available Endpoints

- /sign

  - Request

    - Method
      - POST
    - Headers
      - Basic authentication header
    - Body
      - A json object containing a single key "documents" and whose value is an array of [document objects](https://sdk.invoicing.eta.gov.eg/documents/invoice-v1-0/#core)

  - Response

    - Body
      - The body of the request with the signature appended to each document.
      - Example:
        - [Request body](docu/input.json)
        - [Response body](docu/output.json)
