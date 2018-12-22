# vt_timesketch
Virustotal Data to Timesketch

# idea

Idea of that script is to get a list of domains / ips and pull timeline relevant infos from VT.
The output should be already timesketchable.

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

