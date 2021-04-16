from peewee import *


db = SqliteDatabase('cache.db')

class DNSRecord(Model):
    question = CharField()
    answer = CharField()
    Atype = CharField()
    Qtype = CharField()
    class Meta:
        database = db
        indexes = [
            (('question' , 'Qtype' , 'Atype' , 'answer') , True)
        ]


class DNSRequest(Model):
    question = CharField()
    req_count = IntegerField(default=1)
    type = CharField()
    
    class Meta:
        database = db
        indexes = [
            (('question' , 'type') , True)
        ]



if __name__ == '__main__':
    db.connect()
    db.create_tables([DNSRecord , DNSRequest])
    print('TABLES CREATED')
    db.close()
