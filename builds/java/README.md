# Java wrapper to use vade-evan

## About

This is Java wrapper project which lets Java Applications use VADE SDK.

## Pre-requisites

- install java
- install maven

## How to build and test

### Go inside vade folder.

```sh
cd vade/
```

### Build lib with Cargo.

To build rust library for java wrapper, cargo build should be compiled with java-lib feature:

```sh
cargo build --release --no-default-features --features did-sidetree,did-read,did-write,didcomm,portable,vc-zkp,java-lib
```

### Build Java project with Maven.

Go to builds/java/vade folder and run following command:

```sh
mvn install
```

### Run JUNIT tests

Junit tests are added to demonstrate VADE functionality and the same code can be taken as a reference, to run junit test execute following command:

```sh
mvn test
```

Note: We don’t need to set java.library.path for maven tests because it is already set in Pom.xml file, and java wrapper loads the library from target folder once cargo build is successfully completed.  

```xml
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-surefire-plugin</artifactId>
        <configuration>
          <argLine>-Djava.library.path=../../../target/release</argLine>
        </configuration>
        <version>${maven-surefire-plugin.version}</version>
      </plugin>
```

### Get the Jar file 

When you run mvn install command , the jar file is generated in /builds/java/vade/target folder