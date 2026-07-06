FROM tomcat:9.0-jdk11

RUN curl -L -o /usr/local/tomcat/lib/ojdbc11.jar https://repo1.maven.org/maven2/com/oracle/database/jdbc/ojdbc11/23.3.0.23.09/ojdbc11-23.3.0.23.09.jar || echo "JDBC download fallback"

COPY webapp/ /usr/local/tomcat/webapps/ROOT/

EXPOSE 8080 8009

CMD ["catalina.sh", "run"]