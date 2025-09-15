/*
###############################
Contributing By Natsuiro_XCN

Infrastructure Layer-2 Access Handler - Site: AREA_51_SECNET

This system was designed to resist intrusion by external actors and unauthorized personnel.
But beneath the layers of formality lies something differentâ€”my trace.

Once, It was exposed a critical flawâ€”ROP chains could reach sys().
I've sealed that pathâ€¦ for now.

[+] TODO : Fix Rop 31/05/2025

-- Natsuiro_XCN
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_QUERY_LEN 1024
#define MAX_INPUT_LEN 256
#define MAX_LINE_LEN 512

char* trim(char* str) {
	char* end;
	while(isspace((unsigned char)*str)) str++;
	if(*str == 0) return str;
	end = str + strlen(str) - 1;
	while(end > str && isspace((unsigned char)*end)) end--;
	end[1] = '\0';
	return str;
}


int eval_single_condition(const char* condition, const char* file_username, const char* file_password) {
	char cond_copy[MAX_QUERY_LEN];
	strcpy(cond_copy, condition);
	
	char* trimmed = trim(cond_copy);
	
	// Parse condition: field = 'value'
	char* equals_pos = strchr(trimmed, '=');
	if (!equals_pos) return 0;
	
	// Get left side (field name)
	char field_name[256];
	int field_len = equals_pos - trimmed;
	strncpy(field_name, trimmed, field_len);
	field_name[field_len] = '\0';
	field_name[strlen(field_name)] = '\0';
	trim(field_name);
	
	// Get right side (value)
	char* value_start = equals_pos + 1;
	while (isspace(*value_start)) value_start++;
	
	char field_value[256];
	strcpy(field_value, value_start);
	trim(field_value);
	
	// Remove quotes from value
	if ((field_value[0] == '\'' || field_value[0] == '"') && 
		(field_value[strlen(field_value)-1] == '\'' || field_value[strlen(field_value)-1] == '"')) {
		field_value[strlen(field_value)-1] = '\0';
		memmove(field_value, field_value + 1, strlen(field_value));
	}
	
	// Compare with actual data
	if (strcasecmp(field_name, "username") == 0) {
		return strcmp(field_value, file_username) == 0;
	} else if (strcasecmp(field_name, "password") == 0) {
		return strcmp(field_value, file_password) == 0;
	}else
	{
		return strcmp(field_name, field_value) == 0;
	}
	
	return 0;
}

// Function to evaluate WHERE condition with AND/OR support
int evaluate_where_clause(const char* where_clause, const char* file_username, const char* file_password) {
	char clause_copy[MAX_QUERY_LEN];
	strcpy(clause_copy, where_clause);
	
	// Handle OR conditions - if any OR condition is true, return true
	if (strcasestr(clause_copy, " or ")) {
		char* or_parts[10];
		int or_count = 0;
		
		// Split by OR
		char* token = strtok(clause_copy, " ");
		char current_condition[MAX_QUERY_LEN] = "";
		
		while (token != NULL) {
			if (strcasecmp(token, "or") == 0) {
				// Evaluate current condition
				if (eval_single_condition(current_condition, file_username, file_password)) {
					return 1; // OR - any true condition makes whole thing true
				}
				strcpy(current_condition, "");
			} else {
				if (strlen(current_condition) > 0) {
					strcat(current_condition, " ");
				}
				strcat(current_condition, token);
			}
			token = strtok(NULL, " ");
		}
		
		// Evaluate last condition after final OR
		if (strlen(current_condition) > 0) {
			if (eval_single_condition(current_condition, file_username, file_password)) {
				return 1;
			}
		}
		
		return 0;
	}
	
	// Handle AND conditions - all must be true
	if (strcasestr(clause_copy, " and ")) {
		char* and_parts[10];
		int and_count = 0;
		
		// Split by AND
		char* token = strtok(clause_copy, " ");
		char current_condition[MAX_QUERY_LEN] = "";
		
		while (token != NULL) {
			if (strcasecmp(token, "and") == 0) {
				// Evaluate current condition
				if (!eval_single_condition(current_condition, file_username, file_password)) {
					return 0; // AND - any false condition makes whole thing false
				}
				strcpy(current_condition, "");
			} else {
				if (strlen(current_condition) > 0) {
					strcat(current_condition, " ");
				}
				strcat(current_condition, token);
			}
			token = strtok(NULL, " ");
		}
		
		// Evaluate last condition after final AND
		if (strlen(current_condition) > 0) {
			if (!eval_single_condition(current_condition, file_username, file_password)) {
				return 0;
			}
		}
		
		return 1;
	}
	
	// Single condition
	return eval_single_condition(clause_copy, file_username, file_password);
}

int prepare_exec_query(char* query) {
	printf("[DEBUG] Executing query: %s\n", query);

	char* ptr = query;
	char* token;
	char* filename = NULL;
	char where_clause[MAX_QUERY_LEN] = "";

	// Parse word by word
	// Skip SELECT
	token = strtok(ptr, " ");
	if (!token || strcasecmp(token, "SELECT") != 0) {
		printf("Error: Only SELECT queries allowed!\n");
		return 0;
	}
	
	// Skip column name (id)
	token = strtok(NULL, " ");
	
	// Skip FROM
	token = strtok(NULL, " ");
	if (!token || strcasecmp(token, "FROM") != 0) {
		printf("Error: Invalid query format!\n");
		return 0;
	}
	
	// Get filename
	token = strtok(NULL, " ");
	if (token) {
		filename = token;
	}
	
	// Skip WHERE
	token = strtok(NULL, " ");
	if (!token || strcasecmp(token, "WHERE") != 0) {
		printf("Error: No WHERE clause!\n");
		return 0;
	}
	
	// Get all WHERE clause
	char* remaining = strtok(NULL, "");
	if (remaining) {
		strcpy(where_clause, remaining);
	}
	
	// Remove comments
	char* comment_pos = strstr(where_clause, "--");
	if (comment_pos) {
		*comment_pos = '\0';
	}
	
	FILE* file = fopen("./data.sql", "r");
	if (!file) {
		printf("Error: Could not open ./data.sql\n");
		return 0;
	}
	
	char line[MAX_LINE_LEN];
	int found_results = 0;
	printf("==========================================\n");
	
	while (fgets(line, sizeof(line), file)) {
		char* trimmed = trim(line);
		if (strlen(trimmed) == 0 || trimmed[0] == '#') continue;
		
		// Parse line format: "id", "username", "password"
		char* id_start = strchr(trimmed, '"');
		if (!id_start) continue;
		id_start++;
		
		char* id_end = strchr(id_start, '"');
		if (!id_end) continue;
		
		char file_id[256];
		int id_len = id_end - id_start;
		strncpy(file_id, id_start, id_len);
		file_id[id_len] = '\0';
		
		// Find username (index 1)
		char* username_start = strchr(id_end + 1, '"');
		if (!username_start) continue;
		username_start++;
		
		char* username_end = strchr(username_start, '"');
		if (!username_end) continue;
		
		char file_username[256];
		int username_len = username_end - username_start;
		strncpy(file_username, username_start, username_len);
		file_username[username_len] = '\0';
		
		// Find password (index 2)
		char* password_start = strchr(username_end + 1, '"');
		if (!password_start) continue;
		password_start++;
		
		char* password_end = strchr(password_start, '"');
		if (!password_end) continue;
		
		char file_password[256];
		int password_len = password_end - password_start;
		strncpy(file_password, password_start, password_len);
		file_password[password_len] = '\0';
		
		// Evaluate WHERE clause for this record
		if (evaluate_where_clause(where_clause, file_username, file_password)) {
			printf("ID: %s\n", file_id);
			found_results++;

			if (found_results == 1) {
				return 1;
			}

		}
	}
	
	fclose(file);
	printf("==========================================\n");
	return 0;
}

void create_sample_data_file() {
	FILE* file = fopen("./data.sql", "w");
	if (!file) {
		printf("Warning: Could not create data.sql file\n");
		return;
	}

	fprintf(file, "\"1\", \"admin\", \"password\"\n");
	fprintf(file, "\"2\", \"Natsuiro\", \"mypass\"\n");
	
	fclose(file);
}

// void helper(void) __attribute__((naked, unused));
// void helper()
// {
// 	__asm__(
// 		".intel_syntax noprefix;"
// 		"pop rax;"
// 		"ret;"
// 		".att_syntax;"
// 	);
// }

char x[30] = "	SECURE LOGIN SYSTEM v2.0\n\n";
void logo()
{
	puts("========================================\n");
	write(1, x, 29);
	puts("========================================\n");
	return;
}
void sys(char *exec)
{
	printf("[!] This function is still on maintenance \"%s\" shall not be called\n", exec);
}
void Broadcast()
{
	char x[0x10];
	scanf("%s", x);
	printf("Broadcasting to our organization ...");
}
void admin(int id)
{
	int choice;
	 while (1) {
		printf("\nChoose an option:\n");
		printf("1. Broadcasting Message\n");
		printf("2. Shell\n");
		printf("3. Exit\n");
		printf("Choice: ");
		
		if (scanf("%d", &choice) != 1) {
			printf("Invalid input!\n");
			while (getchar() != '\n'); // Clear \n buff
			continue;
		}
		
		switch (choice) {
			case 1:
				Broadcast();
				break;
				
			case 2:
				if (id == 2){
					sys("/bin/sh");
				} else {
					puts("[-] Access Denied!");
					exit(1);
				}
				break;
				
			case 3:
				puts("Goodbye!\n");
				exit(0);
				
			default:
				break;
		}
	}
}
void setup()
{
	setbuf(stdin, 0);
	setbuf(stdout, 0);
}

int main() {
	char query[MAX_QUERY_LEN];
	char username[MAX_INPUT_LEN];
	char password[MAX_INPUT_LEN];
	setup();
	logo();
	// Create sample data file
	FILE* test = fopen("./data.sql", "r");
	if (!test) {
		create_sample_data_file();
	} else {
		fclose(test);
	}
	
	printf("\n=== LOGIN PORTAL ===\n");
	printf("Username: ");
	fgets(username, sizeof(username), stdin);
	username[strcspn(username, "\n")] = 0;
		
	printf("Password: ");
	fgets(password, sizeof(password), stdin);
	password[strcspn(password, "\n")] = 0;
	
	sprintf(query, "SELECT id FROM data.sql WHERE username = '%s' AND password = '%s'", username, password);
	int id = prepare_exec_query(query);
	if (id)
	{
		printf("[+] Admin Welcome!\n");
		admin(id);
	} else {
		printf("[!] Access Denined!\n");
		exit(1);
	}
	return 0;
}