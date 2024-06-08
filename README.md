1. The concept of an SQL Injection: The concept of an SQL injection is simple. Since SQL is coded with specific keywords and phrases, an attacker can use those keywords to make an unwanted and malcious SQL statement execute even though they do not have direct access to the database itself. As seen in the catamount bank web page, when the user uses the search bar to search for certian memos, the code behind the webpage uses that user input to search the database for any memo containing that phrase. How an SQL injection attack would look and how it would be run in this context would be that the user would first figure out where the original SQL statement ends, and then put another SQL statement at the back of that in the search tab using doulbe quotes and percentage signs. Since the SQL statement in the original code uses the python to string method on the search term, this search is then concatnated to the original SQL statement and then ran, giving the attacker full access to do whatever they wanted to the database from the user side. The attacker can do everything from viewing all transactions in the data base by using an OR statement and giving a 100% of the time true statement, such as "1" LIKE "%1 or they could enter a whole new executable code such as "DROP table_name". This can all be done without the attacker ever needing full access to the database because of the vulnerability in the code, as all they have to do is put it in the search bar, and since the code uses that input for the SQL statement itself, they have full access to do whatever they want to the code given they know the proper SQL keywords.
2. Steps taken to mitigate the attack: As stated before, a SQL statement must use double quotes for it to execute. If those double quotes are not present, then a new SQL statement cannot be started, and furthermore a SQL injection using an OR statement cannot work as the second true statment must be wrapped in double quotes, such as OR "1" LIKE "%1, and the first conditon can not be ended, like in the example of where we close off the VISA statement with VISA". If we take away that ability by sanitizing the search term input, then the chance of an SQL injection attack siginfically decreases. So what I did was I first sanitized BOTH inputs, the account ID and the search term, making sure that the account ID was in fact an integer and that the search term did not contain any double quotes. How I accomplished this was by using python's built in .replace function, replacing any double quotes found in the search term with nothing (aka search_term.replace('"', '')), making an attempt of an SQL injection statement turn up no results when ran through the webite, but without interferring with the actually search itself, as when you type in VISA or Evil Landlord, it still comes up with the results where that memo is infact found. By doing this we made sure that the user input was not directly made into a string, and made sure that an SQL statement that would be attempted to be put in did not work as the double quotes would not be proccessed due to the sanitization of the search term.
