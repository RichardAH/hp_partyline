/*
    Partyline chat is a hotpocket test contract providing a single threaded conversation
    Code is based on previous code also authored by me: hp_default_appbill
    Code is designed to be extensible into a decentralised twitter clone.

    Compilation: g++ party.cpp -o party

    Author: Richard Holland
    Date: 2019-12-20


    ---- Anatomy of party.table ----
    N records of 256 bytes each, appended in the order they are received
    and ordered by public key when order is otherwise ambiguous
    containing the following fields
    
    --------------------------------------------------------------------
    | 4 bytes    | 4 bytes    | 32 bytes    | 8 bytes    | 208 bytes   |
    | timestamp  | flags      | user pubkey | reserved   | message     |
    --------------------------------------------------------------------


    ---- Application layer protocol ----
    messages are prefixed by a single "type" byte, followed by binary
    v - user requests to view recent messages
    m - user sends a message, this is truncated at 208 bytes if longer
    r - contract sends back some number of message records to the user 
    s - contract acknolwegdes that it has sent the user's message


*/

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <map>
#include <utility>
#include <iostream>

#define DEBUG 0//1
#define KEY_SIZE 32
#define RECORD_SIZE 256
#define MESSAGE_SIZE 208 // this is the size of a tweet

#define FILE_BUFFER_SIZE (64*1024*1024) // this will move 0xffff entries at a time

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

#define TABLE_FILE "party.table"
#define TABLE_FILE_2 "./state/party.table" // if TABLE_FILE can't be found try here

// std::string contains binary 32 byte key (hacky)
std::map<std::string, std::pair<FILE*, FILE*>> users;
FILE * table = NULL;
uint32_t consensus_timestamp = 0;

int valid_hex(char* hex, int len) {
    char* x = hex;
    for (; (x-hex) < len && *x != '\0' && *x != '\n' && *x >= '0' && (*x <= '9' || *x >= 'a' && *x <= 'f' || *x >= 'A' && *x <= 'F'); ++x);
    return x-hex == len;
}



void print_hex(uint8_t* data, int len) {
    for (int c = 0; c < len; ++c)
        printf("%02hhx", data[c]);
}

int compar (const void* p1, const void* p2) {
    for (uint8_t* c1 = (uint8_t*)p1, * c2 = (uint8_t*)p2; c1 - (uint8_t*)p1 < KEY_SIZE; ++c1, ++c2)
        if (*c1 < *c2) return -1;
        else if (*c1 > *c2) return +1;
    return 0;
}

// key_out must be KEY_SIZE*2+1
void key_to_hex(uint8_t* key_in, uint8_t* key_out) {
    for (int i = 0; i < KEY_SIZE; ++i) {
        int hn = key_in[i] >> 4;
        int ln = key_in[i] & 0xf;
        key_out[i*2+0] = ( hn < 10 ? '0' + hn : 'a' + (hn - 10) );
        key_out[i*2+1] = ( ln < 10 ? '0' + ln : 'a' + (ln - 10) );
    }
    key_out[KEY_SIZE*2] = '\0';
}

void key_from_hex(uint8_t* key_in, uint8_t* key_out) {
    for (int c = 0; c < 32; ++c) {
        uint8_t hn = tolower(key_in[c*2]);
        uint8_t ln = tolower(key_in[c*2+1]);
        hn = ( hn >= 'a' ? 10 + (hn - 'a') : hn - '0');
        ln = ( ln >= 'a' ? 10 + (ln - 'a') : ln - '0');
        key_out[c] = (hn * 16) + ln;
    }
}

uint64_t uint64_from_bytes(uint8_t* data) {
    return 
        (((uint64_t)(data[0]))<<56) +
        (((uint64_t)(data[1]))<<48) +
        (((uint64_t)(data[2]))<<40) +
        (((uint64_t)(data[3]))<<32) + 
        (((uint64_t)(data[4]))<<24) +
        (((uint64_t)(data[5]))<<16) +
        (((uint64_t)(data[6]))<<8)  +
        (((uint64_t)(data[7])));
}


void uint64_to_bytes(uint8_t* dest, uint64_t x) {
    for (int j = 0; j < 8; j++) {
        *(dest + (7-j)) = x & 0xff;
        x >>= 8;
    }
}


uint32_t uint32_from_bytes(uint8_t* data) {
    return 
        (((uint64_t)(data[0]))<<24) +
        (((uint64_t)(data[1]))<<16) +
        (((uint64_t)(data[2]))<<8)  +
        (((uint64_t)(data[3])));
}


void uint32_to_bytes(uint8_t* dest, uint32_t x) {
    for (int j = 0; j < 4; j++) {
        *(dest + (4-j)) = x & 0xff;
        x >>= 8;
    }
}


int append_record(uint8_t* record) {
    fseek(table, 0, SEEK_END);
    return fwrite(record, 1, RECORD_SIZE, table);
}

#define FETCH_COUNT 1000
int read_from_timestamp(uint32_t timestamp, FILE* send_to) {

    // seek up to 1000 messages previously
    fseek(table, 0, SEEK_END);
    size_t size = ftell(table);

    if (size > FETCH_COUNT*RECORD_SIZE)
        fseek(table, size-FETCH_COUNT*RECORD_SIZE, SEEK_SET);
    else 
        fseek(table, 0, SEEK_SET);


    char data[FETCH_COUNT*RECORD_SIZE];
    size_t bytes_read = MIN(size, RECORD_SIZE*FETCH_COUNT);
    if (fread(data, 1, RECORD_SIZE*FETCH_COUNT, table) != bytes_read) {
        fprintf(stderr, "could not read %lu bytes from table file\n", bytes_read);
        return 0;
    }

    fwrite("r", 1, 1, send_to);

    for (int i = 0; i < bytes_read; i+= RECORD_SIZE) {
        uint32_t ts = uint32_from_bytes((uint8_t*)(data + i));
        if (ts < timestamp)
            continue;
        fwrite(data + i, 1, bytes_read - i, send_to);
        return (bytes_read - i)/RECORD_SIZE;
    }
    
    return 0; 
}



void open_table() {
    if (table) return;

    table = fopen(TABLE_FILE, "rb+");
    if (!table )
        table = fopen(TABLE_FILE_2, "rb+");

    if (!table) {
        fprintf(stderr, "could not open %s or %s\n", TABLE_FILE, TABLE_FILE_2);
        exit( 128 );
    }
}

void close_table() {
    if (table)
        fclose(table);
    table = NULL;
}


void app() {

    int counter = 0;

    // the map will sort by user for us so there should be no conflict between nodes (hopefully!)
    for (auto& [k, v]: users) {
        if (DEBUG)
            fprintf(v.second, "you are user %d\n", counter++);

        char userinp[1024];
        memset(userinp, 0, 1024);
        if (fgets(userinp, 1024, v.first)) {

            // user has provided some input, check what it was
            if (userinp[0] == 'v') {
                // they want to view the most recent messages, so send those
                uint32_t timestamp = 0;
                if (!sscanf(userinp+1, "%d", &timestamp)) {
                    if (DEBUG) 
                        printf("user supplied invalid timestamp with v\n"); 
                    continue;
                }

                read_from_timestamp(timestamp, v.second);
            
            } else if (userinp[0] == 'm') {
                // they want to add a message
                uint8_t* msg = (uint8_t*)(userinp+1);
                uint8_t* key = (uint8_t*)(k.c_str());
   
                uint8_t newrecord[RECORD_SIZE];
                memset(newrecord, 0, RECORD_SIZE);
    
                // write the timestamp at position 0
                uint32_to_bytes(newrecord, consensus_timestamp);
        
                // write the user public key at position 8
                for (int i = 0; i < KEY_SIZE; ++i)
                    newrecord[8+i] = key[i];

                // write the message at position 48
                for (int i = 0; i < MESSAGE_SIZE; ++i)
                    newrecord[48+i] = msg[i]; 

                append_record(newrecord);

                fwrite("s", 1, 1, v.second);
            }
        
            //fprintf(v.second, "your input was `%s`\n", userinp);
        }
    }
}


int main(int argc, char** argv) {
    // full argc, argv are in tact in this mode

    
    open_table();

    // first thing is to read the fdlist

    char buf[1024];
    int mode = 0;
    int bytes_read = 0;

    int counter = 0;
    int toskip = 0;

    uint8_t key[KEY_SIZE];
    int userfdin = 0, userfdout = 0;

    // this is the world's worst json parse, but it is efficient
    do {
        char c = 0;
        bytes_read = 0;
        while ( (c = getc( stdin )) != EOF && c != ',' && c != '{' && c != '}' && c != '[' && c != ']' && c != '\n' && c != ':' && bytes_read < 1023 ) {
            buf[bytes_read++] = c;
        }

        if (c == EOF)
            break;

        if (mode == 2)
            continue;

        buf[bytes_read] = '\0';

        if (DEBUG)
            printf("symbol: `%s`\n", buf);

        if (mode == 0 && strcmp("\"ts\"", buf) == 0) {
            mode = 3;
        } else if (mode == 3) {
            if (DEBUG)
                printf("timestamp was: `%s`\n", buf);
            
            uint64_t ts = 0;
            // not convinced sscanf works correctly for 64 bit ints
            int len = strlen(buf);
            for (int x = 0; x < len; ++x) {
                int digit = buf[x] - '0';
                ts += digit;
                ts *= 10;
            }

            consensus_timestamp = (uint32_t)(ts / 1000);

            if (DEBUG)
                printf("timestamp parsed: %lu\n", ts);

            mode = 0;
        } else  if (mode == 0 && strcmp("\"usrfd\"", buf) == 0)  {
            mode = 1;
            continue;
        }  else if ( mode == 1 && c == '}' ) {
            mode = 2;
            continue;
        }

        if (buf[0] == '\0' || mode != 1)
            continue;
        
        ++counter %= 3;

        // this runs if there's an error in the user's public key
        if (toskip) {
            toskip--;
            continue;
        }
        

        if (DEBUG)
            printf("mode=%d counter=%d component `%s`\n", mode, counter%3, buf);

        if (counter == 1) {
            // this is the user key
            // remove trailing "
            if (!buf[strlen(buf)-1] == '"')
                continue;
            buf[strlen(buf)-1] = '\0';

            // check the key is valid
            if (DEBUG)
                printf("key length: %lu, proper length: %d\n", strlen(buf+3), KEY_SIZE*2);
            if (DEBUG)
                printf("hex: `%s`\n", buf+3);
            if (strlen(buf+3) != KEY_SIZE*2 || !valid_hex(buf+3, KEY_SIZE*2)) {
                toskip = 2;
                if (DEBUG)
                    printf("invald public key %s\n", buf+3);
                continue;
            }

            key_from_hex((uint8_t*)buf+3, key);
            if (DEBUG) {
                printf("parsed key: ");
                print_hex(key, KEY_SIZE);
                printf("\n");
            }

            userfdin = 0; userfdout = 0;
        } else if (counter == 2) {
            // this is the user's input fd

            if (!sscanf(buf, "%d", &userfdin))
                continue;

            if (DEBUG) printf("mode=2 counter=%d userfdin=%d\n", counter, userfdin);

            // there might be some bytes pending on this input, if there are we need to bill for them, one coin per byte
            
            /*int nbytes = 0;
            ioctl(userfd, FIONREAD, &nbytes);*/

        } else if (counter == 0) {
            if (!sscanf(buf, "%d", &userfdout))
                continue;

            if (DEBUG) printf("mode=2 counter=%d userfdout=%d\n", counter, userfdout);

            if (!userfdin || !userfdout) {
                if (DEBUG) {
                    printf("one of the fdlist user's fds could not parse fdin=%d, fdout=%d, key=", userfdin, userfdout);
                    print_hex(key, KEY_SIZE);
                    printf("\n");
                }
                continue;
            } 

            

            // add user to the map
            std::string skey ( (char*)key, (size_t)(KEY_SIZE) );
            FILE* uin = fdopen(userfdin, "r");
            FILE* uout = fdopen(userfdout, "w");

            if (!uin || !uout) {
                if (DEBUG) {
                    printf("could not fdopen either user fd %d or fd %d or both\n", userfdin, userfdout);
                    perror("");
                    continue;
                }
            }
            users[ skey ] = { uin, uout }; 
            
        }

    } while (!feof(stdin)); 
   

    if (DEBUG) {
        std::cout << "key map:\n";   
        for (auto& [ skey, value ] : users) {
            char hex[KEY_SIZE*2+1];
            key_to_hex((uint8_t*)(skey.c_str()), (uint8_t*)hex);
            std::cout << hex << ": " << fileno(value.first) << ", " << fileno(value.second) << "\n";
        } 
    }

    app();
    
    close_table();   
 
    return 0; 
}

