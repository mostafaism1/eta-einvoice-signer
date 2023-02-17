# ETA E-Invoice Signer

## Description

- A web application for signing e-invoice documents in accordance with the [algorithm](https://sdk.invoicing.eta.gov.eg/signature-creation) specified by the Egyptian Tax Authority (ETA).

## Installation

### Requirements

- JDK 17
  - Oracle JDK 17 can be downloaded from [here](https://www.oracle.com/java/technologies/javase/jdk17-archive-downloads.html).

### Building

- Clone the repository to your local environment:

  ```console
  git clone https://github.com/mostafaism1/eta-einvoice-signer
  ```

  ```console
  cd eta-einvoice-signer
  ```

- Build the project:

  ```console
  ./mvnw clean package
  ```

- The previous step will output the following artifact in the target directory: `eta-einvoice-signer`

### Configuration

- Configuration properties should be placed in the `application.properties` file at `eta-einvoice-signer/WEB-INF/classes` (see below for all available configuration properties.)

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

### Deployment

- Deploy the directory `eta-einvoice-signer` to a java application server such as tomcat.

## Usage

### Available Endpoints

- /eta-einvoice-signer

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
