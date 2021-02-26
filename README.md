#Where's Obama 2.0

Last year, I did a project where I effectively implemented Twitter4J in golang. Using the my Twitter4J implementation, I made a program called Where's Obama which finds how far a given user is from Obama based on who they are following.

This year, I decided to expand on that project as it had quite a few issues. The first major thing I did was upgrade to Twitter API 2.0 which is currently in its early access state. This will future proof my program so that future generations can see its majesty. When upgrading to Twitter 2.0 I also upgraded my code to OAUTH 2.0 which is currently the industry standard for authentication and authorization in a REST API environment. The second major thing I did was overhaul the Where's Obama algorithm because in certain edge cases it gave incorrect results. The last thing I did has add actual error checking which uses go's error API. This made the code a lot better to read as well as write. I also made some minor changes like adding actual parsing.

All of the old code is still in the file, but if you want to look at the new code, all of the methods have a 2 in their name.


How to use the program:
Simply run the exe in a command line and enter a handle. If the handle is valid, it should return how many "levels" a person is. If the person is directly following Obama they are 0 levels away. If one of the people they are following follows Obama, it is 1 level and so on.
