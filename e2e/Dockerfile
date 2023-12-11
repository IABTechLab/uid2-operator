######################
# Build dependencies #
######################
FROM maven:3.9.1-eclipse-temurin-17

WORKDIR /app

COPY ./pom.xml ./pom.xml
COPY ./src ./src

######################
# Configure env vars #
######################
ENV UID2_E2E_ENV "github-test-pipeline"

ENV UID2_E2E_SITE_ID "999"
ENV UID2_E2E_API_KEY "UID2-C-L-999-fCXrMM.fsR3mDqAXELtWWMS+xG1s7RdgRTMqdOH2qaAo="
ENV UID2_E2E_API_SECRET "DzBzbjTJcYL0swDtFs2krRNu+g1Eokm2tBU4dEuD0Wk="
ENV UID2_E2E_API_KEY_OLD "UID2-C-L-1000-qxpBsF.ibeCDBpD2bq4Zm7inDacGioUk1aaLeNJrabow="
ENV UID2_E2E_API_SECRET_OLD "VT7+t0G/RVueMuVZAL56I2c3JJFSYQfhbu8yo0V/Tds="

ENV UID2_E2E_IDENTITY_SCOPE "UID2"
ENV UID2_E2E_PHONE_SUPPORT "true"

ENV UID2_E2E_PIPELINE_OPERATOR_URL ""
ENV UID2_E2E_PIPELINE_OPERATOR_TYPE "PUBLIC"
ENV UID2_E2E_PIPELINE_OPERATOR_CLOUD_PROVIDER ""

CMD \
  if [ "$UID2_E2E_PIPELINE_OPERATOR_TYPE" != "PUBLIC" ] && [ "$UID2_E2E_PIPELINE_OPERATOR_TYPE" != "PRIVATE" ] ; \
  then \
    echo "ERROR: Incorrect operator type: $UID2_E2E_PIPELINE_OPERATOR_TYPE" ; \
  elif [ "$UID2_E2E_PIPELINE_OPERATOR_TYPE" = "PUBLIC" ] ; \
  then \
    mvn test -Dtest="E2EPublicOperatorTestSuite" ; \
  else \
    mvn test -Dtest="E2EPrivateOperatorTestSuite" ; \
  fi