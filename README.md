# osint_timesketch
OSINT Data to Timesketch

# idea

Idea of that script is to get a list of domains / ips and pull timeline relevant infos from VT and other OSINT sources.
The output should be already timesketchable.

# WARNING

This project should be considered early aplha, everything might be completly
broken. Run the script on your own risk.

Using that script with high critical indicators might burn your indicators because the script is querying external
meaning internet hosted services. Thus those running those services could potentially see your queries.

# Sources

## already implemented
* Virustotal (files)
* Virustotal (passive DNS)
* CIRCL passive SSL

## planned

* CIRCL passive DNS
* CIRCL passive SSL calculate first seen date based on isci (https://notary.icsi.berkeley.edu/)
    * first_seen: the day our data providers first saw the certificate (relative to 1/1/1970)


# usage
 
   modify the config file
```
cp config_sample.cfg config.cfg
```

   paste your md5 hashes, ips, domains to the input.txt file
   run the script:
  ```
  python vt_lookup.py
   ```
   
   see the output in output.csv
   Copy output csv and add it to your timesketch instance.
   
   Happy digging
   
# sample data

See sample folder.

# Future features

In the future it would be nice to also include data from First submitted, first seen in the wild from VT, but that is not yet explosed via API

