"""TraceAtlas 140-domain metadata. Offline capability != production qualification."""
from __future__ import annotations
from importlib import import_module

_RAW = """OSINT|web_socmint|url,title,source_name,published_at|0
SOCMINT|web_socmint|platform,post_id,engagement,created_at|0
HUMINT|identity_entity|statement,interview_date,consent,source_reliability|1
COMINT|infra_cyber|channel,protocol,duration,collection_authority|1
SIGINT|infra_cyber|frequency_hz,bandwidth_hz,timestamp,collection_authority|1
ELINT|infra_cyber|emitter_id,frequency_hz,signal_type,collection_authority|1
MASINT|geo_media|sensor_id,measurement,unit,calibration|1
GEOINT|geo_media|latitude,longitude,accuracy_m,observed_at|0
IMINT|geo_media|image_hash,width,height,capture_time|0
VIDINT|geo_media|duration_s,fps,frames,codec|0
AUDINT|geo_media|duration_s,sample_rate,codec,transcript|0
TECHINT|infra_cyber|product,version,manufacturer,capability|0
CYBINT|infra_cyber|asset,threat,event_type,severity|0
CTI|cti_malware|indicator,threat_actor,technique,confidence|0
FININT|fin_scam|amount,currency,transaction_date,counterparty|0
CORPINT|corporate_public_records|company,lei,registry_id,jurisdiction|0
ORGINT|corporate_public_records|organization,unit,role,reporting_to|0
TRADEINT|corporate_public_records|hs_code,commodity,origin,destination|0
SUPPLYCHAININT|corporate_public_records|supplier,buyer,part_id,origin|0
ACADEMICINT|corporate_public_records|doi,title,authors,publication_date|0
DECEPTIONINT|hypothesis_analysis|claim,signal,alternative_explanation,evidence_refs|1
WEBINT|web_socmint|url,title,status_code,content_type|0
SEARCHINT|web_socmint|query,result_url,rank,snippet|0
DORKINT|web_socmint|query,operator,result_url,scope|0
ARCHIVEINT|web_socmint|original_url,snapshot_url,snapshot_date,digest|0
NEWSINT|web_socmint|headline,outlet,published_at,url|0
DATASETINT|document_forensics|dataset,columns,row_count,license|0
DOCINT|document_forensics|document_id,title,author,created_at|0
METADATAINT|document_forensics|filename,created_at,modified_at,exif|0
TEXTINT|document_forensics|text,language,word_count,source|0
LANGINT|document_forensics|language,text,translated_text,detected_language|0
NARRATIVEINT|web_socmint|narrative,theme,source_count,timeline|0
DISINFOINT|web_socmint|claim,evidence_refs,verified_status,context|0
MISINFOINT|web_socmint|claim,evidence_refs,verified_status,context|0
PROPINT|web_socmint|message,technique,context,evidence_refs|0
SENTIMENTINT|web_socmint|text,positive_terms,negative_terms,context|0
MEMEINT|web_socmint|caption,template,origin,first_seen|0
FORUMINT|web_socmint|forum,thread_id,posted_at,post_text|0
MESSENGERINT|web_socmint|channel,message_id,timestamp,consent|1
EMAILINT|document_forensics|from_addr,to_addr,subject,date|0
PHONEINT|identity_entity|phone_number,country_code,consent,source|1
USERNAMEINT|identity_entity|username,platform,profile_url,verified|0
IDENTITYINT|identity_entity|identifier,name,source,consent|1
PERSONAINT|identity_entity|persona_id,claims,channels,timestamps|1
RELATIONINT|graph_timeline|subject,predicate,object,relationship_type|0
NETWORKINT|graph_timeline|nodes,edges,degree,community|0
EVENTINT|graph_timeline|event_id,event_time,location,participants|0
TIMELINEINT|graph_timeline|event_time,description,source,timezone|0
DOMAININT|infra_cyber|domain,registrar,expires_at,nameservers|0
DNSINT|infra_cyber|domain,record_type,value,ttl|0
IPINT|infra_cyber|ip,asn,country,network|0
ASNINT|infra_cyber|asn,organization,prefixes,country|0
BGPINT|infra_cyber|prefix,as_path,origin_asn,timestamp|0
NETINT|infra_cyber|cidr,protocol,port,service|0
INFRAINT|infra_cyber|host,provider,region,asset_type|0
CERTINT|infra_cyber|issuer,subject,not_after,fingerprint|0
TLSINT|infra_cyber|tls_version,cipher,not_after,hostname|0
CLOUDINT|infra_cyber|provider,service,region,account_alias|0
HOSTINT|infra_cyber|hostname,os,agent_version,last_seen|0
ROUTEINT|infra_cyber|destination,next_hop,hop_count,route_source|0
CDNINT|infra_cyber|cdn_provider,hostname,pop,cache_status|0
MAILINT|infra_cyber|mx,spf,dmarc,domain|0
IOCINT|cti_malware|indicator,type,first_seen,last_seen|0
TTPINT|cti_malware|technique_id,tactic,procedure,source|0
THREATACTORINT|cti_malware|actor_alias,campaigns,source,confidence|1
CAMPAIGNINT|cti_malware|campaign_id,start_time,end_time,indicators|0
MALINT|cti_malware|sha256,family,file_type,analysis_date|0
EXPLOITINT|cti_malware|cve,advisory_url,known_exploited,disclosed_at|0
VULNINT|cti_malware|cve,cvss,affected_product,fixed_version|0
EXPOSUREINT|cti_malware|asset,exposure,configuration,risk_score|0
BREACHINT|cti_malware|incident_id,disclosed_at,affected_org,source|1
CREDINT|cti_malware|exposure_id,affected_service,credential_type,redacted|1
INCIDENTINT|cti_malware|incident_id,detected_at,status,severity|0
LOGINT|cti_malware|timestamp,event_type,host,severity|0
DFIRINT|cti_malware|artifact_type,hash,collected_at,chain_of_custody|0
HUNTINT|cti_malware|hypothesis,query,result_count,scope|0
DETECTIONINT|cti_malware|rule_id,technique_id,false_positive_rate,source|0
REPOINT|infra_cyber|repository,stars,default_branch,license|0
PACKAGEINT|infra_cyber|package,version,ecosystem,license|0
SBOMINT|infra_cyber|components,format,sbom_version,generated_at|0
DEPENDENCYINT|infra_cyber|package,dependencies,version,ecosystem|0
CODEINT|infra_cyber|language,filename,source_code,repository|0
DEVINT|infra_cyber|developer,repository,commit_count,platform|0
CICDINT|infra_cyber|workflow,runner,permissions,triggers|0
APPINT|infra_cyber|application,version,framework,exposure|0
MOBILEINT|infra_cyber|app_id,platform,permissions,version|0
IOTINT|infra_cyber|device_id,manufacturer,firmware,network|0
OTINT|infra_cyber|asset_id,zone,protocol,criticality|0
ICSINT|infra_cyber|controller,protocol,asset_id,zone|0
APIINT|infra_cyber|endpoint,method,auth_type,rate_limit|0
CWEINT|cti_malware|cwe,category,description,mitigation|0
FRAUDINT|fin_scam|scheme,transactions,discrepancy_amount,case_id|0
SCAMINT|fin_scam|report_id,channel,claimed_organization,loss_amount|0
PAYMENTINT|fin_scam|payment_id,amount,currency,settlement_status|0
CRYPTOINT|fin_scam|chain,tx_hash,block_number,value|0
MARKETPLACEINT|fin_scam|seller,listing_id,price,currency|0
BRANDINT|web_socmint|brand,mentions,channel,first_seen|0
ADINT|web_socmint|campaign,creative,impressions,spend|0
JOBINT|corporate_public_records|employer,role,location,posted_at|0
COMPLAINTINT|fin_scam|complaint_id,category,submitted_at,resolution|0
REPUTATIONINT|web_socmint|entity,source,score,review_count|0
TRUSTINT|evidence_verification|source,accuracy,independence,transparency|0
SOURCEINT|evidence_verification|source_id,origin,methodology,published_at|0
PROVENANCEINT|evidence_verification|source_id,content_hash,collected_at,collector|0
CORROBORATIONINT|evidence_verification|claim,source_ids,source_groups,agreement|0
CONTRADICTIONINT|hypothesis_analysis|claim,conflicting_claim,source_ids,timestamp|0
VERIFICATIONINT|evidence_verification|claim,evidence_refs,method,verdict|0
HYPOTHESISINT|hypothesis_analysis|hypothesis,evidence_refs,alternatives,test|0
FALSIFICATIONINT|hypothesis_analysis|hypothesis,disconfirming_evidence,test,conclusion|0
OWNERSHIPINT|corporate_public_records|entity,owner,percent,as_of|0
REGINT|corporate_public_records|regulator,filing_id,date,entity|0
LEGALINT|corporate_public_records|case_number,court,judgment_date,parties|0
SANCTIONSINT|corporate_public_records|entity,list_name,listing_id,screened_at|1
PROCUREMENTINT|corporate_public_records|tender_id,buyer,supplier,contract_value|0
CONTRACTINT|corporate_public_records|contract_id,party_a,party_b,effective_date|0
ADDRESSINT|identity_entity|address,city,country,source|1
PROPERTYINT|corporate_public_records|property_id,owner,location,valuation|1
ASSETINT|corporate_public_records|asset_id,owner,asset_type,valuation|0
TAXINT|corporate_public_records|tax_period,filing_id,jurisdiction,tax_amount|0
INSOLVENCYINT|corporate_public_records|case_id,entity,proceeding_date,status|0
MNAINT|corporate_public_records|acquirer,target,deal_value,announced_at|0
GOVINT|corporate_public_records|agency,document_id,publication_date,subject|0
POLICYINT|corporate_public_records|policy_id,authority,issued_at,subject|0
DIPLOINT|corporate_public_records|country_a,country_b,statement_date,topic|0
NGOINT|corporate_public_records|ngo,registration_id,mission,filing_date|0
EDUINT|corporate_public_records|institution,program,accreditation,location|0
PATENTINT|corporate_public_records|patent_id,inventor,assignee,filing_date|0
IPRINT|corporate_public_records|ipr_type,registration_id,owner,status|0
STANDARDSINT|corporate_public_records|standard_id,issuer,version,publication_date|0
RNDINT|corporate_public_records|project,organization,funding,phase|0
INNOVATIONINT|corporate_public_records|technology,readiness_level,patents,organizations|0
MARKETINT|corporate_public_records|market,segment,revenue,currency|0
COMPETITORINT|corporate_public_records|company,product,market_share,period|0
CUSTOMERINT|corporate_public_records|segment,feedback,count,period|0
VENDORINT|corporate_public_records|vendor,service,contract,status|0
LOGISTICSINT|geo_media|shipment_id,origin,destination,eta|0
TRANSPORTINT|geo_media|mode,origin,destination,departure_time|0
MARITIMEINT|geo_media|vessel_id,mmsi,lat,lon|0
AVIATIONINT|geo_media|icao24,flight_number,lat,lon|0
RAILINT|geo_media|train_id,station,scheduled_arrival,actual_arrival|0"""
CATALOG = {}
for _line in _RAW.strip().splitlines():
    _code, _family, _fields, _sensitive = _line.split("|")
    CATALOG[_code] = dict(code=_code, family=_family, fields=tuple(_fields.split(",")),
                          sensitive=(_sensitive == "1"), state="offline_adapter",
                          live_verified=False, allowed_tools=())
assert len(CATALOG) == 140

def lookup(code: str) -> dict:
    name = str(code).strip().upper()
    if name not in CATALOG:
        raise KeyError(f"Unsupported intelligence domain: {name}")
    return dict(CATALOG[name])

def load(code: str):
    name = lookup(code)["code"]
    return import_module("." + name.lower(), __package__ + ".modules")
