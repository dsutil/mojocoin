/****************************************************************************
** Meta object code from reading C++ file 'walletmodel.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.2.1)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../src/qt/walletmodel.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'walletmodel.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.2.1. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
struct qt_meta_stringdata_WalletModel_t {
    QByteArrayData data[38];
    char stringdata[484];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    offsetof(qt_meta_stringdata_WalletModel_t, stringdata) + ofs \
        - idx * sizeof(QByteArrayData) \
    )
static const qt_meta_stringdata_WalletModel_t qt_meta_stringdata_WalletModel = {
    {
QT_MOC_LITERAL(0, 0, 11),
QT_MOC_LITERAL(1, 12, 14),
QT_MOC_LITERAL(2, 27, 0),
QT_MOC_LITERAL(3, 28, 7),
QT_MOC_LITERAL(4, 36, 7),
QT_MOC_LITERAL(5, 44, 5),
QT_MOC_LITERAL(6, 50, 18),
QT_MOC_LITERAL(7, 69, 15),
QT_MOC_LITERAL(8, 85, 17),
QT_MOC_LITERAL(9, 103, 16),
QT_MOC_LITERAL(10, 120, 14),
QT_MOC_LITERAL(11, 135, 18),
QT_MOC_LITERAL(12, 154, 20),
QT_MOC_LITERAL(13, 175, 23),
QT_MOC_LITERAL(14, 199, 6),
QT_MOC_LITERAL(15, 206, 13),
QT_MOC_LITERAL(16, 220, 7),
QT_MOC_LITERAL(17, 228, 5),
QT_MOC_LITERAL(18, 234, 5),
QT_MOC_LITERAL(19, 240, 5),
QT_MOC_LITERAL(20, 246, 9),
QT_MOC_LITERAL(21, 256, 8),
QT_MOC_LITERAL(22, 265, 6),
QT_MOC_LITERAL(23, 272, 18),
QT_MOC_LITERAL(24, 291, 9),
QT_MOC_LITERAL(25, 301, 11),
QT_MOC_LITERAL(26, 313, 12),
QT_MOC_LITERAL(27, 326, 9),
QT_MOC_LITERAL(28, 336, 22),
QT_MOC_LITERAL(29, 359, 14),
QT_MOC_LITERAL(30, 374, 12),
QT_MOC_LITERAL(31, 387, 17),
QT_MOC_LITERAL(32, 405, 17),
QT_MOC_LITERAL(33, 423, 7),
QT_MOC_LITERAL(34, 431, 5),
QT_MOC_LITERAL(35, 437, 6),
QT_MOC_LITERAL(36, 444, 19),
QT_MOC_LITERAL(37, 464, 18)
    },
    "WalletModel\0balanceChanged\0\0CAmount\0"
    "balance\0stake\0unconfirmedBalance\0"
    "immatureBalance\0anonymizedBalance\0"
    "watchOnlyBalance\0watchOnlyStake\0"
    "watchUnconfBalance\0watchImmatureBalance\0"
    "encryptionStatusChanged\0status\0"
    "requireUnlock\0message\0title\0modal\0"
    "style\0coinsSent\0CWallet*\0wallet\0"
    "SendCoinsRecipient\0recipient\0transaction\0"
    "showProgress\0nProgress\0notifyWatchonlyChanged\0"
    "fHaveWatchonly\0updateStatus\0"
    "updateTransaction\0updateAddressBook\0"
    "address\0label\0isMine\0updateWatchOnlyFlag\0"
    "pollBalanceChanged\0"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_WalletModel[] = {

 // content:
       7,       // revision
       0,       // classname
       0,    0, // classinfo
      12,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       7,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    9,   74,    2, 0x06,
      13,    1,   93,    2, 0x06,
      15,    0,   96,    2, 0x06,
      16,    4,   97,    2, 0x06,
      20,    3,  106,    2, 0x06,
      26,    2,  113,    2, 0x06,
      28,    1,  118,    2, 0x06,

 // slots: name, argc, parameters, tag, flags
      30,    0,  121,    2, 0x0a,
      31,    0,  122,    2, 0x0a,
      32,    4,  123,    2, 0x0a,
      36,    1,  132,    2, 0x0a,
      37,    0,  135,    2, 0x0a,

 // signals: parameters
    QMetaType::Void, 0x80000000 | 3, 0x80000000 | 3, 0x80000000 | 3, 0x80000000 | 3, 0x80000000 | 3, 0x80000000 | 3, 0x80000000 | 3, 0x80000000 | 3, 0x80000000 | 3,    4,    5,    6,    7,    8,    9,   10,   11,   12,
    QMetaType::Void, QMetaType::Int,   14,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::Bool, QMetaType::UInt,   17,   16,   18,   19,
    QMetaType::Void, 0x80000000 | 21, 0x80000000 | 23, QMetaType::QByteArray,   22,   24,   25,
    QMetaType::Void, QMetaType::QString, QMetaType::Int,   17,   27,
    QMetaType::Void, QMetaType::Bool,   29,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::Bool, QMetaType::Int,   33,   34,   35,   14,
    QMetaType::Void, QMetaType::Bool,   29,
    QMetaType::Void,

       0        // eod
};

void WalletModel::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        WalletModel *_t = static_cast<WalletModel *>(_o);
        switch (_id) {
        case 0: _t->balanceChanged((*reinterpret_cast< const CAmount(*)>(_a[1])),(*reinterpret_cast< const CAmount(*)>(_a[2])),(*reinterpret_cast< const CAmount(*)>(_a[3])),(*reinterpret_cast< const CAmount(*)>(_a[4])),(*reinterpret_cast< const CAmount(*)>(_a[5])),(*reinterpret_cast< const CAmount(*)>(_a[6])),(*reinterpret_cast< const CAmount(*)>(_a[7])),(*reinterpret_cast< const CAmount(*)>(_a[8])),(*reinterpret_cast< const CAmount(*)>(_a[9]))); break;
        case 1: _t->encryptionStatusChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 2: _t->requireUnlock(); break;
        case 3: _t->message((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2])),(*reinterpret_cast< bool(*)>(_a[3])),(*reinterpret_cast< uint(*)>(_a[4]))); break;
        case 4: _t->coinsSent((*reinterpret_cast< CWallet*(*)>(_a[1])),(*reinterpret_cast< SendCoinsRecipient(*)>(_a[2])),(*reinterpret_cast< QByteArray(*)>(_a[3]))); break;
        case 5: _t->showProgress((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< int(*)>(_a[2]))); break;
        case 6: _t->notifyWatchonlyChanged((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 7: _t->updateStatus(); break;
        case 8: _t->updateTransaction(); break;
        case 9: _t->updateAddressBook((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2])),(*reinterpret_cast< bool(*)>(_a[3])),(*reinterpret_cast< int(*)>(_a[4]))); break;
        case 10: _t->updateWatchOnlyFlag((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 11: _t->pollBalanceChanged(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        void **func = reinterpret_cast<void **>(_a[1]);
        {
            typedef void (WalletModel::*_t)(const CAmount & , const CAmount & , const CAmount & , const CAmount & , const CAmount & , const CAmount & , const CAmount & , const CAmount & , const CAmount & );
            if (*reinterpret_cast<_t *>(func) == static_cast<_t>(&WalletModel::balanceChanged)) {
                *result = 0;
            }
        }
        {
            typedef void (WalletModel::*_t)(int );
            if (*reinterpret_cast<_t *>(func) == static_cast<_t>(&WalletModel::encryptionStatusChanged)) {
                *result = 1;
            }
        }
        {
            typedef void (WalletModel::*_t)();
            if (*reinterpret_cast<_t *>(func) == static_cast<_t>(&WalletModel::requireUnlock)) {
                *result = 2;
            }
        }
        {
            typedef void (WalletModel::*_t)(const QString & , const QString & , bool , unsigned int );
            if (*reinterpret_cast<_t *>(func) == static_cast<_t>(&WalletModel::message)) {
                *result = 3;
            }
        }
        {
            typedef void (WalletModel::*_t)(CWallet * , SendCoinsRecipient , QByteArray );
            if (*reinterpret_cast<_t *>(func) == static_cast<_t>(&WalletModel::coinsSent)) {
                *result = 4;
            }
        }
        {
            typedef void (WalletModel::*_t)(const QString & , int );
            if (*reinterpret_cast<_t *>(func) == static_cast<_t>(&WalletModel::showProgress)) {
                *result = 5;
            }
        }
        {
            typedef void (WalletModel::*_t)(bool );
            if (*reinterpret_cast<_t *>(func) == static_cast<_t>(&WalletModel::notifyWatchonlyChanged)) {
                *result = 6;
            }
        }
    }
}

const QMetaObject WalletModel::staticMetaObject = {
    { &QObject::staticMetaObject, qt_meta_stringdata_WalletModel.data,
      qt_meta_data_WalletModel,  qt_static_metacall, 0, 0}
};


const QMetaObject *WalletModel::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *WalletModel::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_WalletModel.stringdata))
        return static_cast<void*>(const_cast< WalletModel*>(this));
    return QObject::qt_metacast(_clname);
}

int WalletModel::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 12)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 12;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 12)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 12;
    }
    return _id;
}

// SIGNAL 0
void WalletModel::balanceChanged(const CAmount & _t1, const CAmount & _t2, const CAmount & _t3, const CAmount & _t4, const CAmount & _t5, const CAmount & _t6, const CAmount & _t7, const CAmount & _t8, const CAmount & _t9)
{
    void *_a[] = { 0, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)), const_cast<void*>(reinterpret_cast<const void*>(&_t3)), const_cast<void*>(reinterpret_cast<const void*>(&_t4)), const_cast<void*>(reinterpret_cast<const void*>(&_t5)), const_cast<void*>(reinterpret_cast<const void*>(&_t6)), const_cast<void*>(reinterpret_cast<const void*>(&_t7)), const_cast<void*>(reinterpret_cast<const void*>(&_t8)), const_cast<void*>(reinterpret_cast<const void*>(&_t9)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void WalletModel::encryptionStatusChanged(int _t1)
{
    void *_a[] = { 0, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}

// SIGNAL 2
void WalletModel::requireUnlock()
{
    QMetaObject::activate(this, &staticMetaObject, 2, 0);
}

// SIGNAL 3
void WalletModel::message(const QString & _t1, const QString & _t2, bool _t3, unsigned int _t4)
{
    void *_a[] = { 0, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)), const_cast<void*>(reinterpret_cast<const void*>(&_t3)), const_cast<void*>(reinterpret_cast<const void*>(&_t4)) };
    QMetaObject::activate(this, &staticMetaObject, 3, _a);
}

// SIGNAL 4
void WalletModel::coinsSent(CWallet * _t1, SendCoinsRecipient _t2, QByteArray _t3)
{
    void *_a[] = { 0, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)), const_cast<void*>(reinterpret_cast<const void*>(&_t3)) };
    QMetaObject::activate(this, &staticMetaObject, 4, _a);
}

// SIGNAL 5
void WalletModel::showProgress(const QString & _t1, int _t2)
{
    void *_a[] = { 0, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)) };
    QMetaObject::activate(this, &staticMetaObject, 5, _a);
}

// SIGNAL 6
void WalletModel::notifyWatchonlyChanged(bool _t1)
{
    void *_a[] = { 0, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 6, _a);
}
QT_END_MOC_NAMESPACE
