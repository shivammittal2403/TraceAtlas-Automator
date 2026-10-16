# Employee input recipes

All 140 recipes contain nonempty synthetic records in the production input contract.
They run offline without API keys. Review flags in examples deliberately demonstrate
conflicts, unknowns and limits; they are not real investigations or verified conclusions.

~~~console
python "EMPLOYEES PYTHON.py" analyze DNSINT --input examples/employees/recipes/DNSINT.json
python "EMPLOYEES PYTHON.py" team --input examples/employees/all140.json --output all140-review.json
~~~

Use the same field shapes with your authorized supplied evidence. Replace synthetic
source URNs with its real provenance and preserve stable record/source identifiers.
For canonical case tasks omit task_id and use the approved lifecycle.

| Employee | Runnable input | Records |
| --- | --- | ---: |
| ACADEMICINT | [ACADEMICINT.json](examples/employees/recipes/ACADEMICINT.json) | 2 |
| ADDRESSINT | [ADDRESSINT.json](examples/employees/recipes/ADDRESSINT.json) | 2 |
| ADINT | [ADINT.json](examples/employees/recipes/ADINT.json) | 1 |
| APIINT | [APIINT.json](examples/employees/recipes/APIINT.json) | 1 |
| APPINT | [APPINT.json](examples/employees/recipes/APPINT.json) | 2 |
| ARCHIVEINT | [ARCHIVEINT.json](examples/employees/recipes/ARCHIVEINT.json) | 1 |
| ASNINT | [ASNINT.json](examples/employees/recipes/ASNINT.json) | 1 |
| ASSETINT | [ASSETINT.json](examples/employees/recipes/ASSETINT.json) | 2 |
| AUDINT | [AUDINT.json](examples/employees/recipes/AUDINT.json) | 1 |
| AVIATIONINT | [AVIATIONINT.json](examples/employees/recipes/AVIATIONINT.json) | 1 |
| BGPINT | [BGPINT.json](examples/employees/recipes/BGPINT.json) | 1 |
| BRANDINT | [BRANDINT.json](examples/employees/recipes/BRANDINT.json) | 2 |
| BREACHINT | [BREACHINT.json](examples/employees/recipes/BREACHINT.json) | 2 |
| CAMPAIGNINT | [CAMPAIGNINT.json](examples/employees/recipes/CAMPAIGNINT.json) | 2 |
| CDNINT | [CDNINT.json](examples/employees/recipes/CDNINT.json) | 1 |
| CERTINT | [CERTINT.json](examples/employees/recipes/CERTINT.json) | 1 |
| CICDINT | [CICDINT.json](examples/employees/recipes/CICDINT.json) | 1 |
| CLOUDINT | [CLOUDINT.json](examples/employees/recipes/CLOUDINT.json) | 1 |
| CODEINT | [CODEINT.json](examples/employees/recipes/CODEINT.json) | 1 |
| COMINT | [COMINT.json](examples/employees/recipes/COMINT.json) | 3 |
| COMPETITORINT | [COMPETITORINT.json](examples/employees/recipes/COMPETITORINT.json) | 3 |
| COMPLAINTINT | [COMPLAINTINT.json](examples/employees/recipes/COMPLAINTINT.json) | 1 |
| CONTRACTINT | [CONTRACTINT.json](examples/employees/recipes/CONTRACTINT.json) | 1 |
| CONTRADICTIONINT | [CONTRADICTIONINT.json](examples/employees/recipes/CONTRADICTIONINT.json) | 2 |
| CORPINT | [CORPINT.json](examples/employees/recipes/CORPINT.json) | 2 |
| CORROBORATIONINT | [CORROBORATIONINT.json](examples/employees/recipes/CORROBORATIONINT.json) | 2 |
| CREDINT | [CREDINT.json](examples/employees/recipes/CREDINT.json) | 2 |
| CRYPTOINT | [CRYPTOINT.json](examples/employees/recipes/CRYPTOINT.json) | 2 |
| CTI | [CTI.json](examples/employees/recipes/CTI.json) | 2 |
| CUSTOMERINT | [CUSTOMERINT.json](examples/employees/recipes/CUSTOMERINT.json) | 4 |
| CWEINT | [CWEINT.json](examples/employees/recipes/CWEINT.json) | 4 |
| CYBINT | [CYBINT.json](examples/employees/recipes/CYBINT.json) | 1 |
| DATASETINT | [DATASETINT.json](examples/employees/recipes/DATASETINT.json) | 1 |
| DECEPTIONINT | [DECEPTIONINT.json](examples/employees/recipes/DECEPTIONINT.json) | 2 |
| DEPENDENCYINT | [DEPENDENCYINT.json](examples/employees/recipes/DEPENDENCYINT.json) | 6 |
| DETECTIONINT | [DETECTIONINT.json](examples/employees/recipes/DETECTIONINT.json) | 3 |
| DEVINT | [DEVINT.json](examples/employees/recipes/DEVINT.json) | 5 |
| DFIRINT | [DFIRINT.json](examples/employees/recipes/DFIRINT.json) | 1 |
| DIPLOINT | [DIPLOINT.json](examples/employees/recipes/DIPLOINT.json) | 2 |
| DISINFOINT | [DISINFOINT.json](examples/employees/recipes/DISINFOINT.json) | 4 |
| DNSINT | [DNSINT.json](examples/employees/recipes/DNSINT.json) | 3 |
| DOCINT | [DOCINT.json](examples/employees/recipes/DOCINT.json) | 1 |
| DOMAININT | [DOMAININT.json](examples/employees/recipes/DOMAININT.json) | 2 |
| DORKINT | [DORKINT.json](examples/employees/recipes/DORKINT.json) | 1 |
| EDUINT | [EDUINT.json](examples/employees/recipes/EDUINT.json) | 1 |
| ELINT | [ELINT.json](examples/employees/recipes/ELINT.json) | 1 |
| EMAILINT | [EMAILINT.json](examples/employees/recipes/EMAILINT.json) | 1 |
| EVENTINT | [EVENTINT.json](examples/employees/recipes/EVENTINT.json) | 2 |
| EXPLOITINT | [EXPLOITINT.json](examples/employees/recipes/EXPLOITINT.json) | 1 |
| EXPOSUREINT | [EXPOSUREINT.json](examples/employees/recipes/EXPOSUREINT.json) | 2 |
| FALSIFICATIONINT | [FALSIFICATIONINT.json](examples/employees/recipes/FALSIFICATIONINT.json) | 3 |
| FININT | [FININT.json](examples/employees/recipes/FININT.json) | 1 |
| FORUMINT | [FORUMINT.json](examples/employees/recipes/FORUMINT.json) | 2 |
| FRAUDINT | [FRAUDINT.json](examples/employees/recipes/FRAUDINT.json) | 6 |
| GEOINT | [GEOINT.json](examples/employees/recipes/GEOINT.json) | 1 |
| GOVINT | [GOVINT.json](examples/employees/recipes/GOVINT.json) | 2 |
| HOSTINT | [HOSTINT.json](examples/employees/recipes/HOSTINT.json) | 1 |
| HUMINT | [HUMINT.json](examples/employees/recipes/HUMINT.json) | 2 |
| HUNTINT | [HUNTINT.json](examples/employees/recipes/HUNTINT.json) | 3 |
| HYPOTHESISINT | [HYPOTHESISINT.json](examples/employees/recipes/HYPOTHESISINT.json) | 3 |
| ICSINT | [ICSINT.json](examples/employees/recipes/ICSINT.json) | 3 |
| IDENTITYINT | [IDENTITYINT.json](examples/employees/recipes/IDENTITYINT.json) | 2 |
| IMINT | [IMINT.json](examples/employees/recipes/IMINT.json) | 2 |
| INCIDENTINT | [INCIDENTINT.json](examples/employees/recipes/INCIDENTINT.json) | 2 |
| INFRAINT | [INFRAINT.json](examples/employees/recipes/INFRAINT.json) | 2 |
| INNOVATIONINT | [INNOVATIONINT.json](examples/employees/recipes/INNOVATIONINT.json) | 1 |
| INSOLVENCYINT | [INSOLVENCYINT.json](examples/employees/recipes/INSOLVENCYINT.json) | 3 |
| IOCINT | [IOCINT.json](examples/employees/recipes/IOCINT.json) | 3 |
| IOTINT | [IOTINT.json](examples/employees/recipes/IOTINT.json) | 3 |
| IPINT | [IPINT.json](examples/employees/recipes/IPINT.json) | 1 |
| IPRINT | [IPRINT.json](examples/employees/recipes/IPRINT.json) | 2 |
| JOBINT | [JOBINT.json](examples/employees/recipes/JOBINT.json) | 2 |
| LANGINT | [LANGINT.json](examples/employees/recipes/LANGINT.json) | 2 |
| LEGALINT | [LEGALINT.json](examples/employees/recipes/LEGALINT.json) | 2 |
| LOGINT | [LOGINT.json](examples/employees/recipes/LOGINT.json) | 3 |
| LOGISTICSINT | [LOGISTICSINT.json](examples/employees/recipes/LOGISTICSINT.json) | 1 |
| MAILINT | [MAILINT.json](examples/employees/recipes/MAILINT.json) | 1 |
| MALINT | [MALINT.json](examples/employees/recipes/MALINT.json) | 1 |
| MARITIMEINT | [MARITIMEINT.json](examples/employees/recipes/MARITIMEINT.json) | 1 |
| MARKETINT | [MARKETINT.json](examples/employees/recipes/MARKETINT.json) | 3 |
| MARKETPLACEINT | [MARKETPLACEINT.json](examples/employees/recipes/MARKETPLACEINT.json) | 3 |
| MASINT | [MASINT.json](examples/employees/recipes/MASINT.json) | 1 |
| MEMEINT | [MEMEINT.json](examples/employees/recipes/MEMEINT.json) | 2 |
| MESSENGERINT | [MESSENGERINT.json](examples/employees/recipes/MESSENGERINT.json) | 2 |
| METADATAINT | [METADATAINT.json](examples/employees/recipes/METADATAINT.json) | 1 |
| MISINFOINT | [MISINFOINT.json](examples/employees/recipes/MISINFOINT.json) | 4 |
| MNAINT | [MNAINT.json](examples/employees/recipes/MNAINT.json) | 2 |
| MOBILEINT | [MOBILEINT.json](examples/employees/recipes/MOBILEINT.json) | 1 |
| NARRATIVEINT | [NARRATIVEINT.json](examples/employees/recipes/NARRATIVEINT.json) | 4 |
| NETINT | [NETINT.json](examples/employees/recipes/NETINT.json) | 1 |
| NETWORKINT | [NETWORKINT.json](examples/employees/recipes/NETWORKINT.json) | 2 |
| NEWSINT | [NEWSINT.json](examples/employees/recipes/NEWSINT.json) | 2 |
| NGOINT | [NGOINT.json](examples/employees/recipes/NGOINT.json) | 1 |
| ORGINT | [ORGINT.json](examples/employees/recipes/ORGINT.json) | 3 |
| OSINT | [OSINT.json](examples/employees/recipes/OSINT.json) | 2 |
| OTINT | [OTINT.json](examples/employees/recipes/OTINT.json) | 7 |
| OWNERSHIPINT | [OWNERSHIPINT.json](examples/employees/recipes/OWNERSHIPINT.json) | 3 |
| PACKAGEINT | [PACKAGEINT.json](examples/employees/recipes/PACKAGEINT.json) | 3 |
| PATENTINT | [PATENTINT.json](examples/employees/recipes/PATENTINT.json) | 2 |
| PAYMENTINT | [PAYMENTINT.json](examples/employees/recipes/PAYMENTINT.json) | 4 |
| PERSONAINT | [PERSONAINT.json](examples/employees/recipes/PERSONAINT.json) | 2 |
| PHONEINT | [PHONEINT.json](examples/employees/recipes/PHONEINT.json) | 2 |
| POLICYINT | [POLICYINT.json](examples/employees/recipes/POLICYINT.json) | 1 |
| PROCUREMENTINT | [PROCUREMENTINT.json](examples/employees/recipes/PROCUREMENTINT.json) | 2 |
| PROPERTYINT | [PROPERTYINT.json](examples/employees/recipes/PROPERTYINT.json) | 2 |
| PROPINT | [PROPINT.json](examples/employees/recipes/PROPINT.json) | 1 |
| PROVENANCEINT | [PROVENANCEINT.json](examples/employees/recipes/PROVENANCEINT.json) | 2 |
| RAILINT | [RAILINT.json](examples/employees/recipes/RAILINT.json) | 1 |
| REGINT | [REGINT.json](examples/employees/recipes/REGINT.json) | 2 |
| RELATIONINT | [RELATIONINT.json](examples/employees/recipes/RELATIONINT.json) | 2 |
| REPOINT | [REPOINT.json](examples/employees/recipes/REPOINT.json) | 4 |
| REPUTATIONINT | [REPUTATIONINT.json](examples/employees/recipes/REPUTATIONINT.json) | 2 |
| RNDINT | [RNDINT.json](examples/employees/recipes/RNDINT.json) | 1 |
| ROUTEINT | [ROUTEINT.json](examples/employees/recipes/ROUTEINT.json) | 1 |
| SANCTIONSINT | [SANCTIONSINT.json](examples/employees/recipes/SANCTIONSINT.json) | 2 |
| SBOMINT | [SBOMINT.json](examples/employees/recipes/SBOMINT.json) | 1 |
| SCAMINT | [SCAMINT.json](examples/employees/recipes/SCAMINT.json) | 1 |
| SEARCHINT | [SEARCHINT.json](examples/employees/recipes/SEARCHINT.json) | 2 |
| SENTIMENTINT | [SENTIMENTINT.json](examples/employees/recipes/SENTIMENTINT.json) | 1 |
| SIGINT | [SIGINT.json](examples/employees/recipes/SIGINT.json) | 1 |
| SOCMINT | [SOCMINT.json](examples/employees/recipes/SOCMINT.json) | 3 |
| SOURCEINT | [SOURCEINT.json](examples/employees/recipes/SOURCEINT.json) | 2 |
| STANDARDSINT | [STANDARDSINT.json](examples/employees/recipes/STANDARDSINT.json) | 3 |
| SUPPLYCHAININT | [SUPPLYCHAININT.json](examples/employees/recipes/SUPPLYCHAININT.json) | 1 |
| TAXINT | [TAXINT.json](examples/employees/recipes/TAXINT.json) | 1 |
| TECHINT | [TECHINT.json](examples/employees/recipes/TECHINT.json) | 5 |
| TEXTINT | [TEXTINT.json](examples/employees/recipes/TEXTINT.json) | 2 |
| THREATACTORINT | [THREATACTORINT.json](examples/employees/recipes/THREATACTORINT.json) | 2 |
| TIMELINEINT | [TIMELINEINT.json](examples/employees/recipes/TIMELINEINT.json) | 2 |
| TLSINT | [TLSINT.json](examples/employees/recipes/TLSINT.json) | 2 |
| TRADEINT | [TRADEINT.json](examples/employees/recipes/TRADEINT.json) | 3 |
| TRANSPORTINT | [TRANSPORTINT.json](examples/employees/recipes/TRANSPORTINT.json) | 1 |
| TRUSTINT | [TRUSTINT.json](examples/employees/recipes/TRUSTINT.json) | 1 |
| TTPINT | [TTPINT.json](examples/employees/recipes/TTPINT.json) | 1 |
| USERNAMEINT | [USERNAMEINT.json](examples/employees/recipes/USERNAMEINT.json) | 3 |
| VENDORINT | [VENDORINT.json](examples/employees/recipes/VENDORINT.json) | 1 |
| VERIFICATIONINT | [VERIFICATIONINT.json](examples/employees/recipes/VERIFICATIONINT.json) | 3 |
| VIDINT | [VIDINT.json](examples/employees/recipes/VIDINT.json) | 1 |
| VULNINT | [VULNINT.json](examples/employees/recipes/VULNINT.json) | 1 |
| WEBINT | [WEBINT.json](examples/employees/recipes/WEBINT.json) | 1 |
