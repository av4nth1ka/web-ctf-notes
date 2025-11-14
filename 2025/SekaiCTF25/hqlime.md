
#hql injection to rce

- hql=hibernate query language
- The solution required chaining multiple vulnerabilities across three different containers: `order_service`, `authn_service`, and `mysql`
- The flag was stored in the underlying database of the authn_service container, specifically found in a file named /root/flag.s. The only container exposed externally was the order_service. Both the order_service and authn_service were Java applications utilizing HQL (Hibernate Query Language) to interact with their respective databases (MySQL and an in-memory H2 database).

Vulnerability 1: HQL Injection in order_service (RCE Path):
- The order_service contained an endpoint that was vulnerable to injection through the fields parameter in an HQL query: `select %s from Order o where o.username="%s"`.
- The input validation for fields was severely flawed, designed only to fail if the input consisted of a single non-word character `(Pattern.matches("\\W", token))`, making it trivial to bypass and inject arbitrary HQL.

Vulnerability 2: HQL Injection in authn_service (Oracle Path):
-  The authn_service was also susceptible to HQL injection in the sessionId parameter: `select s from Session s where s.sessionId = "%s"`.
- This vulnerability point, while not directly exploitable from the outside, could be reached by the order_service during its operation and was later leveraged to create a blind file read oracle using H2 database functions like SUBSTRING and FILE_READ.

RCE Gadget Exploitation (JdiInitiator):

- HQL allows the attacker to call constructors of Java classes using the new keyword within the query.
- The jdk.jshell.execution.JdiInitiator was identified as a powerful gadget because its constructor, when called, launches a java executable with command-line arguments that the attacker can control.
- By manipulating the customConnectorArgs arguments, specifically `ARG_QUOTE` and `ARG_HOME`, the attacker could inject a full shell command (`bash -c id>/tmp/win`) that executed on the underlying order_service container.

Final Exfiltration Strategy (Combining Attacks):
- The RCE in the order_service was used to run an elaborate script that first brute-forced the flag contents character-by-character from the authn_service via the blind HQL oracle.
- The RCE script then used the order_service's HQL injection, combined with the embedded native MySQL sql() command, to execute INTO OUTFILE. This command wrote the collected flag content onto the shared file system of the mysql container (/var/lib/mysql-files/flag).
- Finally, the attacker used the order_service injection again to execute LOAD_FILE within MySQL, reading the flag from the shared directory and returning it to the attacker.

The path to solving the challenge involved multiple steps across the containers:
1. Flawed Input Validation in order_service -> HQL Injection in order_service (fields parameter)
2. HQL Injection in order_service -> Java Constructor Injection (new JdiInitiator) -> RCE on order_service container (via argument splitting/injection)
3. HQL Injection in authn_service (sessionId) -> Blind File Read Oracle (via SUBSTRING(FILE_READ('/root/flag.s')))
4. RCE in order_service + Blind Oracle -> Flag Exfiltration (char-by-char from authn_service to order_service RCE environment)
5. RCE in order_service -> MySQL File Write (via HQL sql('... INTO OUTFILE...')) -> MySQL File Read (via HQL sql('LOAD_FILE(...)')) -> Flag Retrieval


reference:

https://www.valgrindc.tf/posts/hqli-me/