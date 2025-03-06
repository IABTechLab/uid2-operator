FROM mcr.microsoft.com/azure-cli:cbl-mariner2.0

RUN az extension add --name confcom

WORKDIR /usr/src

COPY --chmod=775 entrypoint.sh .

ENTRYPOINT ["/usr/src/entrypoint.sh"]
