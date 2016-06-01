#pragma once

#if !defined(INTERCEPT_ENABLED) && !defined(INTERCEPT_CONFIG_MAIN)
#define INTERCEPT_MANUAL(...)
#define INTERCEPT_METHOD(...)
#define INTERCEPT(...)
#define INTERCEPT_VOID_METHOD(...)
#define INTERCEPT_VOID(...)
#else

// If you're going to code in C++ you'd better have a healthy sense of humor...
#define INTERCEPT_STOP_HAMMER_TIME(x) #x
#define INTERCEPT_STRINGIFICATE(x) INTERCEPT_STOP_HAMMER_TIME(x)

#include <stdint.h>
#include <memory.h>
#include <stdio.h>
#include <functional>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <type_traits>
#include <mutex>
#include <atomic>

namespace Intercept {
	struct HashCString {
		inline size_t operator()(const char* str) const {
			auto hash = size_t(2870177450012600261ull);
			auto qwords = (size_t*)str;
#if INTPTR_MAX == INT64_MAX
			auto hasZero = [](size_t v) { return (((v) - 0x0101010101010101ul) & ~(v) & 0x8080808080808080ul); };
			auto rotl64 = [](size_t x, size_t r) { return ((x << r) | (x >> (64 - r))); };

			// We know it's safe to read at least up to the next full page boundary minus 8
			size_t end = ((uintptr_t(str) + 4095) & ~uintptr_t(4095)) - 8;
			while (uintptr_t(qwords) < end) {
				size_t h = *qwords;
				if (hasZero(h))
					break;

				h *= 11400714785074694791ul;
				h = rotl64(h,31);
				h *= 11400714785074694791ul;
				hash ^= h;
				hash = rotl64(hash,27) * 11400714785074694791ul + 9650029242287828579ul;
				++qwords;
			}
#endif
			// Now go a byte at a time, it may not be safe to read beyond the end of the string
			auto bytes = (char*)qwords;
			size_t c;
			while((c=*bytes++)) {
				hash ^= c;
				hash *= 0x01000193;
			}

			return hash;
		}
	};

	struct EqCString {
		inline bool operator()(const char* a, const char* b) const {
			return ::strcmp(a, b) == 0;
		}
	};

	class Context;
	class Hook;
	class Frame;
}

#ifndef INTERCEPT_STACK_BUFFER_SIZE
#define INTERCEPT_STACK_BUFFER_SIZE 524288
#endif

#ifndef INTERCEPT_CONFIG_ENABLED
#define INTERCEPT_CONFIG_ENABLED true
#endif

#define INTERCEPT_NOOP Intercept::gNoop

namespace Intercept {
	extern std::mutex gInternMutex;
	extern std::unordered_set<const char *, HashCString, EqCString> gInterned;
	extern thread_local Context* tlsCtx;
	extern void (*gNoop)(Frame*);

	inline const char* intern(const char* s) {
		std::lock_guard<std::mutex> lock(gInternMutex);
		auto result = gInterned.insert(s);
		return *result.first;
	}
}

#define INTERCEPT_MANUAL(name, ret, self, ...) do { \
	auto ctx = Intercept::Context::get(); \
	if (ctx) { \
		static const char* hName = Intercept::intern(name); \
		auto hook = ctx->getHook(hName, self == nullptr, __FILE__, __LINE__); \
		if (hook->enabled()) { \
			auto frame = ctx->pushFrame(*hook, self, sizeof(ret), ##__VA_ARGS__); \
			if (hook->mocked()) { \
				hook->callMock(frame); \
				if (frame->hasReturn()) return frame->getReturn<ret>(); }}}} while(0)

#define INTERCEPT_MANUAL_VOID(name, self, ...) do { \
	auto ctx = Intercept::Context::get(); \
	if (ctx) { \
		static const char* hName = Intercept::intern(name); \
		auto hook = ctx->getHook(hName, self == nullptr, __FILE__, __LINE__); \
		if (hook->enabled()) { \
			auto frame = ctx->pushFrame(*hook, self, 0, ##__VA_ARGS__); \
			if (hook->mocked()) { \
				hook->callMock(frame); \
				if (frame->hasVoidReturn()) return; }}}} while(0)

#define INTERCEPT(name, ret, ...) INTERCEPT_MANUAL(name, ret, nullptr, ##__VA_ARGS__)
#define INTERCEPT_METHOD(name, ret, ...) INTERCEPT_MANUAL(name, ret, this, ##__VA_ARGS__)
#define INTERCEPT_VOID(name, ...) INTERCEPT_MANUAL_VOID(name, nullptr, ##__VA_ARGS__)
#define INTERCEPT_VOID_METHOD(name, ...) INTERCEPT_MANUAL_VOID(name, this, ##__VA_ARGS__)

namespace Intercept {
	typedef unsigned char byte;

	struct Disabler {
		Hook& hook;

		inline Disabler(Hook& hook);
		inline ~Disabler();
	};

	class Hook {
		const char* _file;
		int _line;
		bool _isMethod;
		bool _wasReached = false;
		bool _enabled = INTERCEPT_CONFIG_ENABLED;
		std::function<void(Frame*)> mock;

	public:
		const char* name;

		Hook() = default;
		Hook(const Hook&) = default;
		Hook(Hook&&) = default;
		inline Hook(const char* name, bool isMethod, const char* file, int line)
			: _file(file), _line(line), _isMethod(isMethod), name(name)
		{}

		inline void setMock(std::function<void(Frame*)>&& f) {
			mock = std::move(f);
		}

		inline void clearMock() {
			memset(&mock, 0, sizeof(mock));
		}

		inline void callMock(Frame* frame) {
			mock(frame);
		}

		inline std::string location() const {
			return _file + (":" + std::to_string(_line));
		}

		inline bool wasReached() const noexcept {
			return _wasReached;
		}

		inline void wasReached(bool val) noexcept {
			_wasReached = val;
		}

		inline bool isMethod() const noexcept {
			return _isMethod;
		}

		inline bool mocked() const noexcept {
			return bool(mock);
		}

		inline bool enabled() const noexcept {
			return _enabled;
		}

		inline void enable() noexcept {
			_enabled = true;
		}

		inline void disable() noexcept {
			_enabled = false;
		}

		inline Disabler disableInScope() noexcept {
			return Disabler(*this);
		}
	};

	inline Disabler::Disabler(Hook& hook) : hook(hook) {
		hook.disable();
	}

	inline Disabler::~Disabler() {
		hook.enable();
	}

	class FrameIterBase {
	protected:
		const Frame* frame;

	public:
		inline FrameIterBase(const Frame* frame=nullptr) : frame(frame) {}

		typedef const Frame value_type;
		typedef const Frame& reference;
		typedef const Frame* pointer;
		typedef std::forward_iterator_tag iterator_category;

		inline bool operator==(FrameIterBase other) const noexcept {
			return frame == other.frame;
		}
		inline bool operator!=(FrameIterBase other) const noexcept {
			return frame != other.frame;
		}
		inline reference operator*() const noexcept {
			return *frame;
		}
		inline pointer operator->() const noexcept {
			return frame;
		}
	};

	class PrevFrameIter : public FrameIterBase {
	public:
		using FrameIterBase::FrameIterBase;

		PrevFrameIter& operator++() noexcept;
		PrevFrameIter operator++(int) noexcept;
	};

	class NextFrameIter: public FrameIterBase {
	public:
		using FrameIterBase::FrameIterBase;

		NextFrameIter& operator++() noexcept;
		NextFrameIter operator++(int) noexcept;
	};

	class FrameList : PrevFrameIter {
		typedef const Frame value_type;
		typedef PrevFrameIter iterator;

	public:
		using PrevFrameIter::PrevFrameIter;

		iterator begin() const noexcept {
			return *this;
		}

		iterator end() const noexcept {
			return iterator();
		}

		bool empty() const {
			return frame != nullptr;
		}

		inline uint32_t count() const noexcept {
			uint32_t count = 0;
			for (auto it=begin(), end = this->end(); it != end; ++it)
				count++;
			return count;
		}
	};

#pragma pack(4)
	class Frame {
		void* _this;
		Hook& _hook;
		uint32_t _ctx;
		uint32_t _prev;
		byte _hasReturn : 1;
		byte _hasVoidReturn : 1;
		byte _argCount;
		uint16_t _size;
		uint16_t _offsets[];

	public:
		inline Frame(Context& ctx, Hook& hook, void* self, uint32_t prev, byte count) :
			_this(self), _hook(hook), _ctx(uint32_t(uintptr_t(this) - uintptr_t(&ctx))),
			_prev(prev), _hasReturn(false), _hasVoidReturn(false), _argCount(count), _size(uint16_t(sizeof(Frame)) + count*2) {}

		inline Hook& hook() const {
			return _hook;
		}

		inline Context& ctx() const {
			return *(Context*)((char*)this - _ctx);
		}

		inline uint32_t totalArgs() const {
			return _argCount;
		}

		const Frame* prev() const;
    	const Frame* next() const;

		template<class T>
		T* getThis() const {
			return (T*)_this;
		}

		template<class T>
		T& getMutable(uint32_t i) {
			return const_cast<T&>(get<T>(i));
		}

		template<class T>
		const T& get(uint32_t i) const {
			if (i >= _argCount)
				throw std::out_of_range("index to Frame::get<T>() out of range");

			return *(T*)((char*)_offsets + _offsets[i]);
		}

		inline bool hasReturn() const noexcept {
			return _hasReturn;
		}

		inline bool hasVoidReturn() const noexcept {
			return _hasVoidReturn;
		}

		template<class T>
		T&& getReturn() {
			if (!_hasReturn)
				throw std::logic_error("return value was not previously set by calling setReturn");

			return (T&&)*(T*)((char*)this + _size);
		}

		template<class T>
		void setReturn(T&& val) {
			_hasReturn = true;
			*(typename std::remove_reference<T>::type*)((char*)this + _size) = std::move(val);
		}

		template<class T>
		void setReturn(const T& val) {
			_hasReturn = true;
			*(typename std::remove_reference<T>::type*)((char*)this + _size) = val;
		}

		void setReturn() {
			_hasVoidReturn = true;
		}
	private:
		template<class T>
		void put(uint32_t i, char* dest, const T& arg) {
			_offsets[i] = uintptr_t(dest) - uintptr_t(_offsets);
			new (dest) T(arg);
			_size += sizeof(arg);
		}

		friend Context;
	};
#pragma pack()

	class Context {
		struct Copier {
			typedef void (*destructor)(void*);
			typedef void (*copyConstructor)(void* dest, const void* src);

			uint32_t pos;
			destructor dtor;
			copyConstructor cctor;

			inline Copier(uint32_t pos, destructor dtor, copyConstructor cctor)
				: pos(pos), dtor(dtor), cctor(cctor)
			{}
			Copier(const Copier&) = default;
			Copier(Copier&&) = default;
		};

		std::unordered_map<const char*,uint32_t> _called;
		std::unordered_map<const char*,Hook*> _hooks;
		std::vector<Copier> _copies;
		uint32_t _count = 0;
		uint32_t pos = 0;
		uint32_t hookAlloc = 0;
		uint32_t bufSize = INTERCEPT_STACK_BUFFER_SIZE/2;
		char* buf;
		const Frame* lastFrame;
		char _buf[INTERCEPT_STACK_BUFFER_SIZE/2];
		Hook _hookStorage[INTERCEPT_STACK_BUFFER_SIZE/2/sizeof(Hook)];

	public:
		inline static Context* get() noexcept {
			return tlsCtx;
		}

		inline Context() : buf(_buf), lastFrame((Frame*)buf) {
			tlsCtx = this;
		}

		inline ~Context() {
			for (auto& c : _copies) {
				c.dtor(buf + c.pos);
			}
			tlsCtx = nullptr;
			if (buf != _buf) {
				delete [] buf;
				buf = nullptr;
			}
			for (auto& hook : _hooks) {
				if (!hook.second->wasReached())
					::fprintf(stderr, "WARNING: hook %s was mocked but never reached!\n", hook.second->name);
			}
		}

		Context(const Context&) = delete;
		Context(Context&&) = delete;

		inline void reset() {
			this->~Context();
			new (this) Context();
		}

		inline void clear() {
			for (auto& c : _copies) {
				c.dtor(buf + c.pos);
			}
			_copies.clear();
			_called.clear();
			// We keep hooks when clearing the Context, use reset() to remove them
			pos = 0;
			_count = 0;
			lastFrame = (Frame*)buf;
		}

		inline void grow() {
			auto newSize = bufSize*2;
			char* newBuf = new char[newSize];
			memcpy(newBuf, buf, bufSize);
			lastFrame = (const Frame*)(newBuf + uintptr_t(lastFrame) - uintptr_t(buf));
			buf = newBuf;
			bufSize = newSize;
			for (auto& c : _copies) {
				char* obj = buf + c.pos;
				c.cctor(newBuf + c.pos, obj);
				c.dtor(obj);
			}
		}

		inline Hook* getHook(const char* name, bool isMethod=false, const char* file="unreached", int line=0)
		{
			// name was already interned by the caller
			Hook* hook = _hookStorage + hookAlloc;
			auto result = _hooks.emplace(name, hook);
			if (result.second) {
				if (hookAlloc == sizeof(_hookStorage)/sizeof(Hook))
					throw std::runtime_error("too many hooks/mocks");

				hookAlloc++;
				new (hook) Hook(name, isMethod, file, line);
				result.first->second = hook;
			} else {
				hook = result.first->second;
			}
			if (line != 0)
				hook->wasReached(true);
			return hook;
		}

		inline void setMock(const char* name, std::function<void(Frame*)>&& f) {
			name = intern(name);
			Hook* hook = getHook(name);
			hook->setMock(std::move(f));
		}

		inline void clearMock(const char* name) {
			name = intern(name);
			if (!_hooks.erase(name))
				throw std::logic_error(std::string("no hook registered for: ") + name);
		}

		inline Frame* createFrame(Hook& hook, const void* self, uint32_t retSize, uint32_t numArgs=0) {
			char* dest = buf+pos;
			auto result = _called.insert({hook.name,pos});
			auto hdrSize = uint32_t(sizeof(Frame)) + numArgs*2 + retSize;

			uint32_t prevPos = 0;
			if (!result.second) {
				prevPos = result.first->second;
				result.first->second = pos;
			}

			pos += hdrSize;
			if (pos >= bufSize)
				grow();

			auto frame = new (dest) Frame(*this, hook, const_cast<void*>(self), prevPos, numArgs);
			lastFrame = frame;
			_count++;
			return frame;
		}

		Frame* pushFrame(Hook& hook, const void* self, uint32_t retSize) {
			return createFrame(hook, self, retSize);
		}

		template<class... Args>
		Frame* pushFrame(Hook& hook, const void* self, uint32_t retSize, const Args&... args) {
			auto frame = createFrame(hook, self, retSize, uint32_t(sizeof...(Args)));
			uint32_t argIndex = 0;
			putArgs(frame, argIndex, args...);
			return frame;
		}

		template<class T, class... Args>
		void putArgs(Frame* frame, uint32_t& argIndex, const T& arg, const Args&... args) {
			putArgs(frame, argIndex++, arg);
			putArgs(frame, argIndex, args...);
		}

		template<class T>
		void putArgs(Frame* frame, uint32_t argIndex, const T& arg) {
			char* dest = buf+pos;
			pos += sizeof(T);
			if (pos >= bufSize)
				grow();

			frame->put(argIndex, dest, arg);
			if (!std::is_trivially_destructible<T>::value || !std::is_trivially_copyable<T>::value) {
				// Use buf and pos here, because we might grow buf, meaning dest might not point to the object anymore
				_copies.emplace_back(pos,
					(Copier::destructor)(void (*)(T*))[](T* obj) { obj->~T(); },
					(Copier::copyConstructor)(void (*)(T*,const T*))[](T* dest, const T* src) { new (dest) T(*src); });
			}
		}

		inline const Frame* operator[](const char* name) const {
			auto it = _called.find(name);
			if (it == _called.end())
				return nullptr;

			return (const Frame*)(buf + it->second);
		}

		inline FrameList allCalls(const char* name) const {
			return FrameList((*this)[name]);
		}

		inline bool called(const char* name) const {
			return (*this)[name] != nullptr;
		}

		inline uint32_t count(const char* name) const {
			return allCalls(name).count();
		}

		inline uint32_t count() const noexcept {
			return _count;
		}

		inline bool empty() const noexcept {
			return _count == 0;
		}

		inline const Frame* back() {
			return lastFrame;
		}

		inline NextFrameIter begin() const {
			return NextFrameIter((Frame*)buf);
		}

		inline NextFrameIter end() const {
			return NextFrameIter(lastFrame->next());
		}

		friend Frame;
	};

	inline PrevFrameIter& PrevFrameIter::operator++() noexcept {
			frame = frame->prev();
			return *this;
	}

	inline PrevFrameIter PrevFrameIter::operator++(int) noexcept {
		auto copy = *this;
		frame = frame->prev();
		return copy;
	}

	inline NextFrameIter& NextFrameIter::operator++() noexcept {
			frame = frame->next();
			return *this;
	}

	inline NextFrameIter NextFrameIter::operator++(int) noexcept {
		auto copy = *this;
		frame = frame->next();
		return copy;
	}

	inline const Frame* Frame::next() const {
		return (this == ctx().lastFrame) ? nullptr : (Frame*)((char*)this + _size);
	}

	inline const Frame* Frame::prev() const {
		return (_prev == 0) ? nullptr : (Frame*)(ctx().buf + _prev);
	}
}


#ifdef INTERCEPT_CONFIG_MAIN

namespace Intercept {
	thread_local Context* tlsCtx = nullptr;
	std::mutex gInternMutex;
	std::unordered_set<const char *, HashCString, EqCString> gInterned;
	void (*gNoop)(Frame*) = [](Frame* f) { f->setReturn(); };
}
#endif

#endif // ifdef INTERCEPT_ENABLED