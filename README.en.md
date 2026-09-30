# IAM

[简体中文](README.md) | English

IAM is an identity and access management project for a single organization and its applications. It lets applications share accounts and sign-in, with centralized management of users, application roles, sessions, and security audits.

## Use cases

- Share accounts and single sign-on across applications operated by your organization.
- Centrally manage user activation, account disabling, password recovery, and application access.
- View and revoke sessions, and trace security-sensitive operations.

IAM manages accounts, authentication, and application-level authorization. Each application enforces permissions for its own business objects and operations.

## Development and runtime

The project uses Spring Boot 4.1.1 and Java 21. Builds require JDK 21 and use the Maven Wrapper included in the repository.

Run the tests and build an executable JAR:

```bash
./mvnw clean verify
```

Start the application:

```bash
java -jar target/iam.jar
```

## Support and maintenance

Report usage issues and improvement suggestions through [GitHub Issues](https://github.com/iXayda/IAM/issues). The project is maintained by ka1i. Contact: <iXayda@outlook.com>.

For vulnerabilities, follow the [security policy](SECURITY.md). Read the [contribution guide](CONTRIBUTING.md) before contributing.

## License

Unless otherwise stated, this project is licensed under the [Apache License 2.0](LICENSE). The [Code of Conduct](CODE_OF_CONDUCT.md) is licensed under CC BY-SA 4.0.
