# Do the following
- run `obtain_cti_report_to_timeML.py`. This will convert every CTI reports to TimeML xml files
- run `convert_timeML_to_json.py`. This will convert TimeML events to noun-phrases or verb-phrases
- run `classify_temporal_events_to_TTPs.py`. This will classify TTPs on the noun and verb phrases
- run `construct_features_from_timeML.py`. This will construct timeML related features per TTPs-pair per reports