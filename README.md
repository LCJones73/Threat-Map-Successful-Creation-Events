# Threat Map Successful Creation Events
Looking inside a network to discover all users who have successfully created resources, like Virtual Machines as an example.

> [!note]
> To better understand this section, consider reviewing the [Threat Maps Creation (Deep Dive)](https://github.com/LCJones73/Threat-Maps-Creating-Deep-Dive) first. I will also be referencing the project on Successful & Failed Logins<BR><BR>

The following code will generate a Threat Map showing all users (callers) who have successfully created resources like Virtual Machines. One thing to note is that in the network we are using as an example, there is an automatd bot running as well. We will want to distinguish between actual live users and the bot in our query.

![image](https://github.com/user-attachments/assets/f7a44568-046d-4c35-a929-ed9bf5d48b41)

This creates the following Threat Map:

![image](https://github.com/user-attachments/assets/34e3a1d3-f542-4bec-ae47-7d1424e0479d)

> [!IMPORTANT]
> Let's Break This KQL Code Down!
>
> ![image](https://github.com/user-attachments/assets/3145b6a4-3d2e-4565-85ba-ab247bcdd31b)
>
> Everything that is done in the network environment creates a log. This isn't just creation events, but also deletion events. Everything is logged and can be seen. In this case we are specifically looking for successful creation events.<BR><BR>
> Now remember, in this particular environment we have a bot running on the network. The first thing this code is doing, is removing this bots actions from the search: | where not(Caller matches regex @"^[{(]?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-_fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}[)}]?$")_<BR><BR>
> Next in this code we are now looking for caller activity: | where CallerIpAddress matches regex _@"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b_"<BR><BR>
> Then we are using the code to look for successfiul "Write" (resource creation) events: | where OperationNameValue endswith "WRITE" and (ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded")
| summarize ResouceCreationCount = count() by Caller, CallerIpAddress;<BR><BR>
> The next section of code is now taking the "Caller" (user) on the network and takes those who have successful creation events and locates them to create the Threat Map.<BR><BR>
> This next section of code starts with "_AzureActivityRecords_" and uses the following code: _| evaluate ipv4_lookup(GeoIPDB_FULL, CallerIpAddress, network)_
>The code using IPV4 is another table which is used to lookup IPV4 Address to location mapping, this is able to prode Geo Location info so we can create the map.<BR><BR>
> While this is not an exhaustive dive into this code, the goal is to help it make sense so that you understand how, at a "fundamental level", the map is created. You can see that this code is a bit more complicated than the code in the Successful and Failed Login events. In that code the difference was an "=" or a "!" to find these log events. This code has to look for more information to achieve the goal.
>
> That ends this project, next we will create a threat map that shows "VM Authentication Failures".
