# bgp_injector
Simple BGP route injection tool. It can be used in a lab environment to advertise thousands of BGP routes.

This is a simple python tool to inject a high number of BGP routes onto a lab routing environment. 

Do not use this on your live network!

I have used this on a Cisco 3745 router and I was able to advertise 235k prefixes before the router got out of memory… 
(take a look at the screenshot).

o use this tool just edit the config file named bgp_injector.cfg to set the number of BGP routes you want to advertise. 
The configuration is very simple but get in touch if you need help. 

Be aware that, just like with the bgp_monitor tool, you need to edit the *.py file to set the BGP peer address.

Cheers!
