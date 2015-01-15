A bunch of useful stuff

# USAGE

Coz some fuckers are too lazy to run the script to check the fucking usage...

Do some nmap / nikto / ... scans with XML output

***SQL database generation***
```
$ scan_utils.rb -t <scan_type> -o my_awesome_scan_results.sqlite <scan_1_result.xml> <scan_2_result.xml> ...
```

You can populate the database in various iterations
So generate the SQLite DB as soon as your scans are done
My advice is to not merge a nmap with and without sC/sV scans, coz it sux ballz
Otherwise, merge whatever with whatever, it should be fine

Now you have a SQLite database with all your results. That's FUCKING AWESOME !!!

But as you probably are as bad as reading SQL stuff as XML stuff, I have something to help you

***HTML reports***
```
$ report_utils.rb my_awesome_scan_results.sqlite
```

Yay, you now have some cool stuff to read named my_awesome_scan_results.html

I strongly recommends to also run that one before generating the HTML report (or re-run it afterward, same same)

***Screenshots for the Awesome HTML report***
```
$ map_utils.rb -a screenshot my_awesome_scan_results.sqlite
```

Now you have screenshots all over the place !!!
Read map_utils.rb usage to put that in some specific directory.

I would stongly recommend to run the following too on internals
But you have to edit some code for various reasons:
 - No thread support so far
 - Speed is not a feature
 - Not inserting stuff in the DB as it is HORRIBLY SLOW
 - You are too dumb to use the --resume switch
So whiners are gonna whine while I have some wine

***Scanning SMB shares in only 50 days***
```
$ map_utils.rb -a smb my_awesome_scan_results.sqlite
```


***Credz for free ? SRSLY ?***

Find shit, collect shit, then (if firefox shit):
```
$ credz_utils.rb -i ./Profiles/blahblahblag.default-6969696969 -t dir -f firefox
[-] http://pwnd.wesite.pwnd -- user -- password
...
```
