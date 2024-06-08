"""
SQL Injection Example
This function is the only one you are permitted
to modify for the lab assignment.

Note: if you aren't familiar with str.format, here
is a link to the docs:
https://docs.python.org/3/library/stdtypes.html#str.format
"""


def create_search_query(account_id: int, search_term: str) -> str:
    """
    Creation of SQL query that has injection vulnerability.
    You should be able to
        1) explain why this is vulnerable,
           - The reason why this SQL query has an injection vulnerability
             is because it directly takes the user's input and puts into
             the SQL query without sanitizing it,
             leading way to the user being able to put in
             harmful commands into the search bar and execute it.
        2) demonstrate how to exploit this vulnerability, and
           - By sanitizing both inputs, we can mitigate the
             risk of a SQL injection attack. For account_id,
             we make sure that is in fact an integer, so that
             an attack cannot go in and modify this input because
             SQL statements require characters, which as we know are
             not integers. For the search term, we sanitize this
             by replacing all double quotes with nothing, as SQL
             statements that would be used in an SQL injection
             attack would need to use double quotes to 1. close
             the initial SQL statement and 2. begin the malicious one.
             By making the double quotes become nothing, this ensures
             that there is no chance for an SQL injection attack, and ensures
             that the attempt of one does not crash our webpage as the search
             term searched would just not turn up anything, and return an
             empty table.
        3) modify this code to prevent SQL injection attack
    :param account_id: int
    :param search_term: str
    :return: str (the query)
    """
    # Never do this in the real world...
    # sanitize both inputs
    account_id = int(account_id)
    search_term = search_term.replace('"','')
    q = 'SELECT * FROM trnsaction ' \
        'WHERE trnsaction.account_id = {} ' \
        'AND ' \
        'trnsaction.memo LIKE "%{}%"'.format(account_id, search_term)
    return q
