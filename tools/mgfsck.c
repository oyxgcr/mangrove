/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLK 4096ULL
#define REC_BYTES 192ULL
#define REC_PER_BLOCK 21ULL
#define BIT_HEADER 24ULL
#define BIT_PER_BLOCK 32576ULL
#define CRC_POLY 0x42F0E1EBA9EA3693ULL
#define EXT_DATA 1ULL
#define EXT_DIR 2ULL
#define EXT_LIST_MAGIC 0x315458455346474DULL
#define EXT_LIST_HEADER 64ULL
#define EXT_LIST_MAX 126ULL
#define DIR_LIVE 1ULL
#define DIR_TOMB 2ULL
#define RECORD_INLINE 1ULL
#define RECORD_OWNER_MASK (0xFFFFFFFFULL << 1)
#define RECORD_PERMISSION_MASK (0xFULL << 33)
#define RECORD_CHILD_MUTATION_OWNER_RESTRICTED (1ULL << 41)
#define RECORD_FLAGS_KNOWN (RECORD_INLINE | RECORD_OWNER_MASK | \
                            RECORD_PERMISSION_MASK | \
                            RECORD_CHILD_MUTATION_OWNER_RESTRICTED)

typedef uint64_t u64; typedef uint8_t u8;
typedef struct { u64 alloc,alloc_blocks,records,record_blocks,table,table_blocks,record_count,data,data_blocks,total,root; } layout_t;
typedef struct { u64 block,record; const char *kind; } owner_t;
static FILE *image; static layout_t fs; static u64 format_minor; static u8 *record_bitmap,*allocation_bitmap,*reachable,*graph_state,*record_type;
static u64 *first_parent,*first_offset,*incoming,*active_path; static size_t active_depth;
static owner_t *owners; static size_t owner_count,owner_capacity; static int errors,warnings,records_checked,dirs_checked,reachable_count;
static int directory_cycles,multiply_referenced,multiply_parented;
static int bitmap_normalized,record_bitmap_flattened,record_bitmap_validated;

static u64 le64(const u8 *p){u64 v=0;for(int i=0;i<8;i++)v|=(u64)p[i]<<(8*i);return v;}
static void put64(u8 *p,u64 v){for(int i=0;i<8;i++)p[i]=(u8)(v>>(8*i));}
static u64 crc64(const u8 *p,size_t n){u64 c=0;for(size_t i=0;i<n;i++){c^=(u64)p[i]<<56;for(int j=0;j<8;j++)c=(c>>63)?(c<<1)^CRC_POLY:c<<1;}return c;}
static void report_error(const char *fmt,...){va_list ap;va_start(ap,fmt);fputs("error: ",stderr);vfprintf(stderr,fmt,ap);fputc('\n',stderr);va_end(ap);errors++;}
static void report_warning(const char *fmt,...){va_list ap;va_start(ap,fmt);fputs("warning: ",stderr);vfprintf(stderr,fmt,ap);fputc('\n',stderr);va_end(ap);warnings++;}
static int add(u64 a,u64 b,u64 *r){if(a>UINT64_MAX-b)return 0;*r=a+b;return 1;}
static int valid_label_extension(const u8 *block);
static int read_block(u64 n,u8 *out){u64 off;if(n>UINT64_MAX/BLK)return 0;off=n*BLK;if((u64)(long)off!=off||fseek(image,(long)off,SEEK_SET)||fread(out,1,BLK,image)!=BLK)return 0;if(n==0&&!valid_label_extension(out))return 0;return 1;}
static int valid_crc(const u8 *data,u64 off,u64 bytes){u8 *tmp=malloc(bytes);if(!tmp)return 0;memcpy(tmp,data,bytes);u64 stored=le64(tmp+off);put64(tmp+off,0);int ok=stored==crc64(tmp,bytes);free(tmp);return ok;}
static int valid_label_extension(const u8 *block){static const u8 magic[8]={'M','G','L','A','B','E','L','1'};int any=0;for(u64 i=200;i<288;i++)if(block[i]){any=1;break;}if(!any)return 1;if(memcmp(block+200,magic,8)||le64(block+208)>63||block[279])return 0;for(u64 i=le64(block+208);i<63;i++)if(block[216+i])return 0;return valid_crc(block+200,80,88);}
static int add_owner(u64 block,u64 record,const char *kind){for(size_t i=0;i<owner_count;i++)if(owners[i].block==block){if(owners[i].record!=record||strcmp(owners[i].kind,kind))report_error("block %"PRIu64" multiply owned: Record %"PRIu64" (%s) and Record %"PRIu64" (%s)",block,owners[i].record,owners[i].kind,record,kind);return 1;}if(owner_count==owner_capacity){size_t n=owner_capacity?owner_capacity*2:256;owner_t *p=realloc(owners,n*sizeof(*p));if(!p)return 0;owners=p;owner_capacity=n;}owners[owner_count++]=(owner_t){block,record,kind};return 1;}
/* On disk, each bitmap block has its own 24-byte header.  The checker keeps
 * record bits as a compact in-memory stream for its legacy record walkers;
 * allocation normalization below converts back to an on-disk-shaped map
 * indexed by physical block. */
static int flatten_bitmap(u8 *bitmap,u64 block_count){
    u8 *flat;
    u64 payload=BIT_PER_BLOCK/8ULL;
    if(!bitmap||block_count>(u64)SIZE_MAX/BLK)return 0;
    flat=calloc((size_t)block_count,(size_t)BLK);
    if(!flat)return 0;
    for(u64 index=0;index<block_count;index++)
        memcpy(flat+BIT_HEADER+index*payload,
               bitmap+index*BLK+BIT_HEADER,(size_t)payload);
    memcpy(bitmap,flat,(size_t)block_count*BLK);
    free(flat);
    return 1;
}
static void normalize_bitmap(void){if(bitmap_normalized)return;if(!flatten_bitmap(allocation_bitmap,fs.alloc_blocks)){report_error("unable to normalize allocation bitmap");bitmap_normalized=1;return;}u8 *raw=malloc(fs.alloc_blocks*BLK);if(!raw){report_error("unable to allocate allocation bitmap scratch");bitmap_normalized=1;return;}memcpy(raw,allocation_bitmap,fs.alloc_blocks*BLK);memset(allocation_bitmap,0,fs.alloc_blocks*BLK);for(u64 n=0;n<fs.data_blocks;n++){if((raw[BIT_HEADER+n/8]>>(n%8))&1){u64 p=fs.data+n;u64 bi=p/BIT_PER_BLOCK,bb=p%BIT_PER_BLOCK;allocation_bitmap[bi*BLK+BIT_HEADER+bb/8]|=(u8)(1U<<(bb%8));}}free(raw);bitmap_normalized=1;}
static void validate_record_bitmap_slots(void){
    if(record_bitmap_validated)return;
    record_bitmap_validated=1;
    if(!record_bitmap_flattened){
        if(!flatten_bitmap(record_bitmap,fs.record_blocks)){
            report_error("unable to normalize Record bitmap");
            return;
        }
        record_bitmap_flattened=1;
    }
    u8 b[BLK];
    for(u64 s=0;s<fs.record_count;s++)if((record_bitmap[BIT_HEADER+s/8]>>(s%8))&1){
        if(!read_block(fs.table+s/REC_PER_BLOCK,b)){
            report_error("Record slot %"PRIu64" table block is unreadable",s);
            continue;
        }
        const u8 *r=b+BIT_HEADER+(s%REC_PER_BLOCK)*REC_BYTES;
        u64 type=le64(r),id=le64(r+16),flags=le64(r+8);
        int empty=1;
        for(u64 i=0;i<REC_BYTES;i++)if(r[i]){empty=0;break;}
        if(empty){
            report_error("Record slot %"PRIu64" is allocated but empty",s);
        }else if(!id||id>fs.record_count||(type!=1&&type!=2)||
                 !valid_crc(r,184,REC_BYTES)||
                 (flags&~RECORD_FLAGS_KNOWN)||
                 (type==1&&(flags&RECORD_CHILD_MUTATION_OWNER_RESTRICTED))||
                 (format_minor==1&&(flags&RECORD_CHILD_MUTATION_OWNER_RESTRICTED))||
                 ((flags>>33&0xFULL)==0)){
            report_error("Record slot %"PRIu64" is allocated but malformed",s);
        }
    }
}
static int record_id_exists(u64 id){
    validate_record_bitmap_slots();
    u8 b[BLK];
    for(u64 s=0;s<fs.record_count;s++)
        if((record_bitmap[BIT_HEADER+s/8]>>(s%8))&1){
            if(!read_block(fs.table+s/REC_PER_BLOCK,b))return 0;
            if(le64(b+BIT_HEADER+(s%REC_PER_BLOCK)*REC_BYTES+16)==id)
                return 1;
        }
    return 0;
}
static int bit(const u8 *map,u64 n){
    if(map==record_bitmap)return record_id_exists(n+1);
    return (map[BIT_HEADER+n/8]>>(n%8))&1;
}
static int record_slot(u64 id,u64 *slot){normalize_bitmap();u8 b[BLK];for(u64 s=0;s<fs.record_count;s++)if((record_bitmap[BIT_HEADER+s/8]>>(s%8))&1){if(!read_block(fs.table+s/REC_PER_BLOCK,b))return 0;if(le64(b+BIT_HEADER+(s%REC_PER_BLOCK)*REC_BYTES+16)==id){*slot=s;return 1;}}return 0;}
static int read_record_slot(u64 slot,u8 out[REC_BYTES]){u8 b[BLK];if(slot>=fs.record_count||!((record_bitmap[BIT_HEADER+slot/8]>>(slot%8))&1)||!read_block(fs.table+slot/REC_PER_BLOCK,b))return 0;memcpy(out,b+BIT_HEADER+(slot%REC_PER_BLOCK)*REC_BYTES,REC_BYTES);return le64(out+16)!=0&&valid_crc(out,184,REC_BYTES)&&((le64(out+8)&~RECORD_FLAGS_KNOWN)==0)&&((le64(out+8)>>33&0xFULL)!=0);}
static int read_record(u64 id,u8 out[REC_BYTES]){u64 s;return record_slot(id,&s)&&read_record_slot(s,out)&&le64(out+16)==id;}
static int add_extent(u64 id,const u8 *e,u64 expected,u64 type,u64 *next){u64 l=le64(e),p=le64(e+8),n=le64(e+16),f=le64(e+24),end;if(!n||l!=*next||f!=type||!add(l,n,&end)||p<fs.data||p-fs.data>=fs.data_blocks||n>fs.data_blocks-(p-fs.data)){report_error("Record %"PRIu64" has an out-of-range or invalid extent",id);return 0;}for(u64 i=0;i<n;i++)add_owner(p+i,id,"data extent");*next=end;return 1;}
static int scan_extents(u64 id,const u8 *r,u64 type,u64 *capacity){if(le64(r+8)&1){*capacity=56;return 1;}u64 total=le64(r+40),inline_count=le64(r+48),next=0,count=0,list=le64(r+56);if(inline_count>2||inline_count>total)return 0;for(u64 i=0;i<inline_count;i++){if(!add_extent(id,r+64+i*32,0,type,&next))return 0;count++;}while(list){u8 b[BLK];if(list<fs.data||list-fs.data>=fs.data_blocks||!read_block(list,b)||le64(b)!=EXT_LIST_MAGIC||le64(b+8)!=id||!valid_crc(b,32,BLK)){report_error("Record %"PRIu64" has an invalid extent-list block %"PRIu64,id,list);return 0;}add_owner(list,id,"extent-list block");u64 n=le64(b+24);if(!n||n>EXT_LIST_MAX)return 0;for(u64 i=0;i<n;i++){if(count>=total||!add_extent(id,b+EXT_LIST_HEADER+i*32,0,type,&next))return 0;count++;}list=le64(b+16);}if(count!=total)return 0;*capacity=next;return 1;}
typedef struct {u64 off,id,len;char name[256];} name_t;
typedef struct {u64 logical,physical,blocks;} stream_extent_t;
typedef struct {stream_extent_t *extents;size_t count;u64 logical_size,capacity_bytes;} directory_stream_t;
static int valid_utf8_name(const u8 *name,u64 length){
    u64 i=0;
    if(!length||length>255||(length==1&&name[0]=='.')||(length==2&&name[0]=='.'&&name[1]=='.'))return 0;
    while(i<length){
        u8 first=name[i++]; u64 count=0;
        if(first==0||first=='/')return 0;
        if(first<0x80)continue;
        if(first>=0xC2&&first<=0xDF)count=1;
        else if(first>=0xE0&&first<=0xEF)count=2;
        else if(first>=0xF0&&first<=0xF4)count=3;
        else return 0;
        if(count>length-i)return 0;
        for(u64 j=0;j<count;j++)if(name[i+j]<0x80||name[i+j]>0xBF||name[i+j]==0||name[i+j]=='/')return 0;
        if((first==0xE0&&name[i]<0xA0)||(first==0xED&&name[i]>0x9F)||(first==0xF0&&name[i]<0x90)||(first==0xF4&&name[i]>0x8F))return 0;
        i+=count;
    }
    return 1;
}
static int stream_add_extent(directory_stream_t *stream,u64 id,const u8 *e){
    u64 logical=le64(e),physical=le64(e+8),blocks=le64(e+16),flags=le64(e+24),end;
    if(!blocks||flags!=EXT_DIR||logical!=stream->capacity_bytes/BLK||
       !add(logical,blocks,&end)||physical<fs.data||physical-fs.data>=fs.data_blocks||
       blocks>fs.data_blocks-(physical-fs.data))return 0;
    for(size_t i=0;i<stream->count;i++)
        if(physical<stream->extents[i].physical+stream->extents[i].blocks&&
           stream->extents[i].physical<physical+blocks)return 0;
    if(stream->count==SIZE_MAX/sizeof(*stream->extents))return 0;
    stream_extent_t *p=realloc(stream->extents,(stream->count+1)*sizeof(*p));
    if(!p)return 0;
    stream->extents=p; stream->extents[stream->count++]=(stream_extent_t){logical,physical,blocks};
    stream->capacity_bytes=end*BLK;
    return 1;
}
static int collect_directory_stream(u64 id,const u8 *record,directory_stream_t *stream){
    u64 total=le64(record+40),inline_count=le64(record+48),list=le64(record+56),lists=0;
    memset(stream,0,sizeof(*stream));
    if(inline_count>2||inline_count>total)return 0;
    for(u64 i=0;i<inline_count;i++)if(!stream_add_extent(stream,id,record+64+i*32))goto fail;
    while(list){
        u8 block[BLK]; u64 entries;
        if(++lists>total||list<fs.data||list-fs.data>=fs.data_blocks||!read_block(list,block)||
           le64(block)!=EXT_LIST_MAGIC||le64(block+8)!=id||!valid_crc(block,32,BLK))goto fail;
        entries=le64(block+24);
        if(!entries||entries>EXT_LIST_MAX||stream->count+entries>total)goto fail;
        for(u64 i=40;i<64;i++)if(block[i])goto fail;
        for(u64 i=0;i<entries;i++)if(!stream_add_extent(stream,id,block+EXT_LIST_HEADER+i*32))goto fail;
        list=le64(block+16);
    }
    if(stream->count!=total)goto fail;
    stream->logical_size=le64(record+32);
    if(stream->logical_size>stream->capacity_bytes)goto fail;
    return 1;
fail:
    free(stream->extents); memset(stream,0,sizeof(*stream)); return 0;
}
static int directory_stream_read(const directory_stream_t *stream,u64 offset,u64 length,u8 *out){
    if(offset>stream->logical_size||length>stream->logical_size-offset)return 0;
    while(length){
        u64 block=offset/BLK,within=offset%BLK; const stream_extent_t *found=NULL;
        for(size_t i=0;i<stream->count;i++)if(block>=stream->extents[i].logical&&block-stream->extents[i].logical<stream->extents[i].blocks){found=&stream->extents[i];break;}
        if(!found)return 0;
        u64 physical;if(!add(found->physical,block-found->logical,&physical))return 0;
        u8 data[BLK]; if(!read_block(physical,data))return 0;
        u64 chunk=BLK-within;if(chunk>length)chunk=length;
        memcpy(out,data+within,(size_t)chunk); out+=chunk; offset+=chunk; length-=chunk;
    }
    return 1;
}
static void report_cycle(u64 source,u64 target,u64 offset){
    fprintf(stderr,"error: directory cycle from Record %"PRIu64" to Record %"PRIu64" at offset %"PRIu64" (path",source,target,offset);
    for(size_t i=0;i<active_depth;i++)fprintf(stderr," %"PRIu64,active_path[i]);
    fprintf(stderr," %"PRIu64")\n",target); errors++; directory_cycles++;
}
static int scan_directory(u64 id,const u8 *r,int reachable_context){
    u64 size=le64(r+32),off=0;
    directory_stream_t stream={0};
    name_t *names=NULL; size_t name_count=0,name_capacity=0; int result=0;
    dirs_checked++;
    if(active_depth>=fs.record_count){report_error("directory traversal depth exceeded at Record %"PRIu64,id);return 0;}
    active_path[active_depth++]=id;
    if(!size){result=1;goto done;}
    if(!collect_directory_stream(id,r,&stream)){
        report_error("invalid directory extents in Record %"PRIu64,id);
        goto done;
    }
    while(off<size){
        u8 header[32],entry[288]; u64 n,len;
        if(!directory_stream_read(&stream,off,32,header))goto malformed;
        n=le64(header+8);
        if(n>255||n>UINT64_MAX-39)goto malformed;
        len=(32+n+7)&~7ULL;
        if(!n||len>288||len>size-off||!directory_stream_read(&stream,off,len,entry)||!valid_crc(entry,24,len)||!valid_utf8_name(entry+32,n))goto malformed;
        for(u64 i=32+n;i<len;i++)if(entry[i])goto malformed;
        {
            u8 *e=entry; u64 flags=le64(e+16),child=le64(e);
            if(flags!=DIR_LIVE&&flags!=DIR_TOMB){
                report_error("directory Record %"PRIu64" has invalid entry flags at offset %"PRIu64,id,off);
                goto done;
            }
            if(flags==DIR_LIVE){
                if(!child||!read_record(child,(u8[REC_BYTES]){0}))
                    report_error("directory Record %"PRIu64" entry at offset %"PRIu64" references free Record %"PRIu64,id,off,child);
                for(size_t i=0;i<name_count;i++) if(names[i].len==n&&!memcmp(names[i].name,e+32,n))
                    report_error("duplicate live name \"%.*s\" in directory Record %"PRIu64" at offsets %"PRIu64" and %"PRIu64" (Records %"PRIu64" and %"PRIu64")",(int)n,e+32,id,names[i].off,off,names[i].id,child);
                if(name_count==name_capacity){
                    size_t next=name_capacity?name_capacity*2:64; name_t *grown;
                    if(next<name_capacity||next>SIZE_MAX/sizeof(*names))goto done;
                    grown=realloc(names,next*sizeof(*names)); if(!grown)goto done;
                    names=grown; name_capacity=next;
                }
                names[name_count].off=off; names[name_count].id=child; names[name_count].len=n;
                memcpy(names[name_count].name,e+32,n); names[name_count].name[n]=0; name_count++;
                {
                    u8 child_record[REC_BYTES];
                    if(read_record(child,child_record)){
                        u64 child_type=le64(child_record);
                        if(child_type==2){
                            if(child==fs.root){
                                report_error("directory Record %"PRIu64" entry at offset %"PRIu64" illegally references root Record",id,off);
                            }
                            if(incoming[child]++==0){first_parent[child]=id;first_offset[child]=off;}
                            else if(first_parent[child]!=id){report_error("directory Record %"PRIu64" has multiply parented directory Record %"PRIu64" (first offset %"PRIu64", second offset %"PRIu64")",first_parent[child],child,first_offset[child],off);multiply_parented++;}
                            else {report_error("directory Record %"PRIu64" references directory Record %"PRIu64" more than once (offsets %"PRIu64" and %"PRIu64")",id,child,first_offset[child],off);multiply_referenced++;}
                            if(graph_state[child]==1)report_cycle(id,child,off);
                            else if(graph_state[child]==0){
                                graph_state[child]=1;
                                if(reachable_context&&!reachable[child]){reachable[child]=1;reachable_count++;}
                                u64 cap=0; scan_extents(child,child_record,EXT_DIR,&cap); scan_directory(child,child_record,reachable_context);
                            }
                        } else if(child_type==1){
                            if(incoming[child]++==0){first_parent[child]=id;first_offset[child]=off;}
                            else {report_error("regular-file Record %"PRIu64" is referenced by multiple live entries (first parent %"PRIu64" offset %"PRIu64", second parent %"PRIu64" offset %"PRIu64")",child,first_parent[child],first_offset[child],id,off);multiply_referenced++;}
                            if(reachable_context&&!reachable[child]){reachable[child]=1;reachable_count++;}
                        }
                    }
                }
            }
        }
        if(!add(off,len,&off))goto done;
    }
    result=1; goto done;
malformed:
    report_error("directory Record %"PRIu64" has malformed entry at offset %"PRIu64,id,off);
done:
    if(active_depth>0)active_depth--;
    graph_state[id]=2;
    free(stream.extents);
    free(names); return result;
}
static int make_layout(u64 total){u64 t=total/320;if(!t)t=1;fs.alloc=1;fs.alloc_blocks=(total+BIT_PER_BLOCK-1)/BIT_PER_BLOCK;fs.records=fs.alloc+fs.alloc_blocks;fs.record_count=t*REC_PER_BLOCK;fs.record_blocks=(fs.record_count+BIT_PER_BLOCK-1)/BIT_PER_BLOCK;fs.table=fs.records+fs.record_blocks;fs.table_blocks=t;fs.data=fs.table+t;fs.data_blocks=total-fs.data;fs.total=total;return fs.data<total;}
static void seed_metadata(void){/* Metadata blocks are outside the allocation bitmap. */}
int main(int argc,char **argv){u8 b[BLK];if(argc!=2){fprintf(stderr,"usage: %s <image>\n",argv[0]);return 2;}image=fopen(argv[1],"rb");if(!image){perror("mgfsck");return 2;}if(fseek(image,0,SEEK_END)||ftell(image)<0){fclose(image);return 2;}u64 total=(u64)ftell(image)/BLK;if(!make_layout(total)){report_error("invalid filesystem geometry");return 1;}if(!read_block(0,b)||memcmp(b,"MGFSv1\0\0",8)||le64(b+8)!=1||(le64(b+16)!=1&&le64(b+16)!=2)||le64(b+24)!=200||le64(b+32)!=BLK||!valid_crc(b,192,200))report_error("invalid superblock");format_minor=le64(b+16);fs.root=le64(b+88);record_bitmap=calloc(fs.record_blocks,BLK);allocation_bitmap=calloc(fs.alloc_blocks,BLK);reachable=calloc(fs.record_count+1,1);graph_state=calloc(fs.record_count+1,1);record_type=calloc(fs.record_count+1,1);first_parent=calloc(fs.record_count+1,sizeof(*first_parent));first_offset=calloc(fs.record_count+1,sizeof(*first_offset));incoming=calloc(fs.record_count+1,sizeof(*incoming));active_path=calloc(fs.record_count+1,sizeof(*active_path));if(!record_bitmap||!allocation_bitmap||!reachable||!graph_state||!record_type||!first_parent||!first_offset||!incoming||!active_path)return 2;seed_metadata();for(u64 i=0;i<fs.alloc_blocks;i++){if(!read_block(fs.alloc+i,b)||le64(b)!=1||le64(b+8)!=i||!valid_crc(b,16,BLK))report_error("invalid allocation bitmap block %"PRIu64,i);else memcpy(allocation_bitmap+i*BLK,b,BLK);}for(u64 i=0;i<fs.record_blocks;i++){if(!read_block(fs.records+i,b)||le64(b)!=2||le64(b+8)!=i||!valid_crc(b,16,BLK))report_error("invalid Record bitmap block %"PRIu64,i);else memcpy(record_bitmap+i*BLK,b,BLK);}for(u64 s=0;s<fs.record_count;s++)if(bit(record_bitmap,s)){u8 r[REC_BYTES];records_checked++;if(!read_record(s+1,r)){report_error("Record %"PRIu64" checksum or ID invalid",s+1);continue;}record_type[s+1]=(u8)le64(r);u64 cap=0;if(!scan_extents(s+1,r,le64(r)==2?EXT_DIR:EXT_DATA,&cap))report_error("invalid extents in Record %"PRIu64,s+1);if(cap>UINT64_MAX/BLK||le64(r+32)>cap*BLK)report_error("Record %"PRIu64" logical size exceeds extents",s+1);}u8 root[REC_BYTES];if(!read_record(fs.root,root)||le64(root)!=2)report_error("root Record is invalid");else{graph_state[fs.root]=1;reachable[fs.root]=1;reachable_count=1;scan_directory(fs.root,root,1);}for(u64 s=0;s<fs.record_count;s++)if(bit(record_bitmap,s)&&record_type[s+1]==2&&graph_state[s+1]==0){u8 r[REC_BYTES];report_warning("Record %"PRIu64" is allocated but unreachable",s+1);graph_state[s+1]=1;scan_directory(s+1,read_record(s+1,r)?r:(u8[REC_BYTES]){0},0);}for(u64 s=0;s<fs.record_count;s++)if(bit(record_bitmap,s)&&!reachable[s+1]&&record_type[s+1]!=2)report_warning("Record %"PRIu64" is allocated but unreachable",s+1);u64 allocated=0,unowned=0;for(u64 n=0;n<fs.total;n++){u64 bi=n/BIT_PER_BLOCK,bb=n%BIT_PER_BLOCK;int allocated_bit=(allocation_bitmap[bi*BLK+BIT_HEADER+bb/8]>>(bb%8))&1;int owned=0;for(size_t j=0;j<owner_count;j++)if(owners[j].block==n){owned=1;break;}if(allocated_bit)allocated++;if(owned&&!allocated_bit)report_error("referenced block %"PRIu64" is marked free",n);if(allocated_bit&&!owned&&n>=fs.data){unowned++;report_warning("allocated block %"PRIu64" has no owner",n);}}printf("MGFS check: %s\nAllocated blocks: %"PRIu64"\nOwned blocks: %zu\nUnowned allocated blocks: %"PRIu64"\nMultiply owned blocks: %d\nRecords checked: %d\nDirectories checked: %d\nReachable Records: %d\nDirectory cycles: %d\nMultiply referenced Records: %d\nMultiply parented directories: %d\nErrors: %d\nWarnings: %d\n",argv[1],allocated,owner_count,unowned,multiply_referenced,records_checked,dirs_checked,reachable_count,directory_cycles,multiply_referenced,multiply_parented,errors,warnings);fclose(image);return errors?1:0;}
