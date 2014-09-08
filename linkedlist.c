
typedef struct linkedList {
    unsigned int source_port, dest_port, ack_no, seq_no;
    unsigned char *payload;
    unsigned int size_payload;
    struct linkedList *next;
} Node;

//Inserting data based on the seq numbers
void list_insert(Node **head, Node *newNode) {
    if(!newNode) return;
    if(head == NULL || *head == NULL ) {
            newNode->next = *head;
             *head = newNode;
            return;
    }
    
    Node *curr = *head, *prev = NULL;
    while(curr && curr -> seq_no < newNode->seq_no) {
        prev = curr;
        curr = curr->next;
    }
    
    if(prev) {
        newNode->next = prev->next;
        prev->next = newNode;
    } else {
        newNode->next = curr;
        *head = newNode;
    }
}

void list_delete(Node **head, Node *node ) {
    if(head == NULL || *head == NULL || node == NULL) {
        return;
    }
    
    Node *prev= NULL, *curr=*head;
    while(curr && curr != node) {
        prev = curr;
        curr = curr->next;
    }
    
    if(! curr) return;
    if(prev) {
        prev -> next = curr -> next;
    } else {
        *head = curr->next;
    }
    free(curr);
}


