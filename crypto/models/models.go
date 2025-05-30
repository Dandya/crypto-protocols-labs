package models

import "hash"

type Mode int

const (
	EncryptMode Mode = 0
	DecryptMode Mode = 1
)

// Интерфейс, реализующий логику вывода сообщений
type Log interface {
	// Простой вывод информации.
	Info(msg string)
	// Вывод информации с сигнализацией об ошибке.
	Error(msg string)
	// Вывод информации с сигнализацией об ошибке и завершением программы.
	Fatal(msg string)
}

// Интерфейс, реализующий логику работы с ключом
type Key interface {
	// Получение части данных.
	GetPart(i int) any
	// Установка части данных.
	Set(i int, v byte)
	// Длина части данных в байтах.
	PartLen() int
	// Длина данных в байтах.
	Len() int
	// Получение среза с данными.
	Data() []byte
	// Очистка данных (зануление).
	Clear()
}

// Интерфейс, реализующий логику работы с блоком данных
type Block interface {
	// Получение части данных.
	GetPart(i int) any
	// Установка части данных.
	SetPart(i int, v any)
	// Получение байта данных.
	Get(i int) byte
	// Установка байта данных.
	Set(i int, v byte)
	// Длина части данных в байтах.
	PartLen() int
	// Длина данных в байтах.
	Len() int
	// Получение среза с данными.
	Data() []byte
	// Очистка данных (зануление).
	Clear()
}

// Интерфейс, реализующий логику работы базового алгоритма шифрования
type BaseAlgorithm interface {
	// Зашифровывает src блок и записывает изменения в dst блок.
	// src и dst для оптимизации могут ссылаться на одни данные.
	Encrypt(key Key, src, dst Block)
	// Расшифровывает src блок и записывает изменения в dst блок.
	// src и dst для оптимизации могут ссылаться на одни данные.
	Decrypt(key Key, src, dst Block)
	// Создание блока необходимого размера.
	NewBlock() Block
	// Создание ключа необходимого размера.
	NewKey() Key
	// Длина блока в байтах.
	BlockLen() int
	// Длина ключа в байтах.
	KeyLen() int
}

// Интерфейс, реализующий логику работы алгоритма дополнения блока данных.
type BlockAdder interface {
	// Возвращает массив, который необходимо добавить к данным.
	GetDataFor(remains_len int, block_len int) []byte
	// Возвращает длину добавленной части по расшифрованным данным.
	GetSizeIn(data []byte) (int, error)
}

// Интерфейс, реализующий логику режима шифрования.
type CryptoModeStream interface {
	// Зашифровывает src блок и записывает изменения в dst блок.
	// src и dst для оптимизации могут ссылаться на одни данные.
	Encrypt(base BaseAlgorithm, key Key, src Block, dst Block)
	// Расшифровывает src блок и записывает изменения в dst блок.
	// src и dst для оптимизации могут ссылаться на одни данные.
	Decrypt(base BaseAlgorithm, key Key, src Block, dst Block)
}

// Интерфейс, реализующий логику вычисления хэша.
type Hasher interface {
	hash.Hash
}

// Интерфейс, реализующий логику вычисления HMAC.
type HMAC interface {
	// Вычисляет HMAC для ключа и данных.
	Sum(key []byte, data []byte) ([]byte, error)
	// Максимально допустимый размер ключа в байтах.
	KeyMaxSize() int
	// Максимальный размер выходных данных.
	MaxSize() int
	// Возвращает базовое состояние хэша в начальное состояние.
	Reset()
}

// Интерфейс, реализующий логику деверсификации ключа.
type KDF interface {
	// Деверсификации ключа
	Create(key []byte, label []byte, seed []byte) ([]byte, error)
	// Максимально допустимый размер ключа в байтах.
	KeyMaxSize() int
	// Максимальный размер выходных данных.
	MaxSize() int
	// Возвращает базовое состояние хэша в начальное состояние.
	Reset()
}

// Структура для передача параметров в KDF.
type KDFParams struct {
	Kdf   KDF
	Key   []byte
	Label []byte
	Seed  []byte
}

// Интерфейс, реализующий логику генератора случайных бит.
type DRBG interface {
	// Проверяет, необходимо ли перезапустить генератор.
	NeedReseed() bool
	// Перезапуск генератора.
	Reseed(entropy, additional []byte) error
	// Генерирует в b len(b) псевдослучайных байт.
	Generate(b, additional []byte) error
	// Возвращает максимальную длину генерируемых данных.
	MaxBytesPerRequest() int
}

// Интерфейс, реализующий логику генератора псевдослучайных данных.
type DRBGPrng interface {
	// Заполняет срез data псевдослучайными данными.
	Read(data []byte) (int, error)
}
