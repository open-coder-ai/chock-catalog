plugins { id("org.springframework.boot") version "3.3.4" }
repositories { mavenCentral(); maven { url = uri("https://packages.acme.com/maven") } }
dependencies {
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("com.thoughtworks.xstream:xstream:1.4.21")
    implementation("com.h2database:h2:2.3.232")
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.0")
}
