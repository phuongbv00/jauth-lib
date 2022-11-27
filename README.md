# JAuth Lib

## 1. Introduction

JAuth Lib is a set of Java modules that boots up your JWT-based authentication tasks faster.

Versions compatibility table:

| JAuth Lib version | Spring Boot version | Spring Cloud version |
|:-----------------:|:-------------------:|:--------------------:|
|       0.0.0       |        2.6.7        |       2021.0.1       |

## 2. Modules

* [JAuth Lib Core](./jauth-lib-core)
* [JAuth Lib Spring Web](./jauth-lib-spring-web)
* [JAuth Lib Spring Gateway](./jauth-lib-spring-gateway)
* [JAuth Lib Demo](./jauth-lib-demo)

## 3. Installation

Add the core dependency first:

```xml

<dependency>
    <groupId>io.github.censodev</groupId>
    <artifactId>jauth-lib-core</artifactId>
    <version>0.0.0</version>
</dependency>
```

```groovy
implementation 'io.github.censodev:jauth-lib-core:0.0.0'
```

If you are handling the authentication tasks with **Spring Web**, add the below dependency:

```xml

<dependency>
    <groupId>io.github.censodev</groupId>
    <artifactId>jauth-lib-spring-web</artifactId>
    <version>0.0.0</version>
</dependency>
```

```groovy
implementation 'io.github.censodev:jauth-lib-spring-web:0.0.0'
```

In opposite, if you are working with **Spring Gateway**, add dependency:

```xml

<dependency>
    <groupId>io.github.censodev</groupId>
    <artifactId>jauth-lib-spring-gateway</artifactId>
    <version>0.0.0</version>
</dependency>
```

```groovy
implementation 'io.github.censodev:jauth-lib-spring-gateway:0.0.0'
```

## 4. Usages

### 4.1. Define the authenticatable entity

You need to create an entity implements the interface ```CanAuth```.
[Go to example](./jauth-lib-demo/src/main/java/io/github/censodev/jauthlibdemo/User.java)

### 4.2. Create a security configuration

At this step, you need to create a configuration with at least 2 beans:

* ```TokenProvider```: Note that, the ```secret``` property is required and has no default value.
* ```SecurityFilterChain```: Create a ```SpringWebAuthFilter``` or ```SpringGatewayAuthFilter``` and register it
  before ```UsernamePasswordAuthenticationFilter```

[Go to example](./jauth-lib-demo/src/main/java/io/github/censodev/jauthlibdemo/SecurityConfig.java)

### 4.3. Generate token

[Go to example](./jauth-lib-demo/src/main/java/io/github/censodev/jauthlibdemo/AuthServiceImpl.java)

### 4.4. Get credential in application runtime

You can use the ```SecurityContextHolder``` to get the token's credential:

```java
class Test {
    void getCredential() {
        Optional<User> u = Optional.ofNullable((User) SecurityContextHolder.getContext().getAuthentication().getCredential());
    }
}
```