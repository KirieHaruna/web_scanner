import pymysql


def creat():
    db = pymysql.connect("localhost", "root", "123456", "sakila")
    cursor = db.cursor()
    cursor.execute("DROP TABLE IF EXISTS BUGINFO")
    sql = """CREATE TABLE BUGINFO (
            URL CHAR(100) NOT NULL,
            PAYLOAD  CHAR(50),
            INJECTABLE CHAR(5),  
            CVSS CHAR(10),
            PARAMETER CHAR(20) )"""

    cursor.execute(sql)
    db.close()


def insert(url, payload, injectable, cvss, parameter):
    db = pymysql.connect("localhost", "root", "123456", "sakila")
    cursor = db.cursor()
    payload = payload.replace("\'","\\\'")
    sql = """INSERT INTO BUGINFO(URL,
         PAYLOAD, INJECTABLE, CVSS, PARAMETER)
         VALUES(' """ + url + "\',\'" + payload + "\',\'" + injectable + "\',\'" + cvss + "\',\'" + parameter + "\')"
    try:
        cursor.execute(sql)
        db.commit()
    except Exception as re:
        print(re)
        print(sql)
        db.rollback()
    db.close()
