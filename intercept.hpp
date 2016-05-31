#pragma once

#if !defined(INTERCEPT_ENABLED) && !defined(INTERCEPT_CONFIG_MAIN)
#define INTERCEPT_MANUAL(...)
#define INTERCEPT_METHOD(...)
#define INTERCEPT(...)
#define INTERCEPT_LOG_MANUAL(...)
#define INTERCEPT_LOG(...)
#define INTERCEPT_LOG_METHOD(...)
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
			return strcmp(a, b) == 0;
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

namespace Intercept {
	extern std::mutex gRegisterMutex;
	extern std::unordered_map<const char *, Hook *, HashCString, EqCString> gHooks;
	extern thread_local Context* tlsCtx;
}

#define INTERCEPT_MANUAL(name, ret, self, ...) do { \
	auto ctx = Intercept::Context::get(); \
	if (ctx) { \
		static Intercept::Hook h; \
		static auto hook = h.registerHook(name, self == nullptr, __FILE__, __LINE__); \
		if (hook->enabled()) { \
			auto frame = ctx->pushFrame(*hook, self, ##__VA_ARGS__); \
			if (hook->mocked()) return hook->callMock<ret>(frame); }}} while(0)

#define INTERCEPT_LOG_MANUAL(name, self, ...) do { \
	auto ctx = Intercept::Context::get(); \
	if (ctx) { \
		static Intercept::Hook h; \
		static auto hook = h.registerHook(name, self == nullptr, __FILE__, __LINE__); \
		if (ctx && hook->enabled()) { \
			auto frame = ctx->pushFrame(*hook, self, ##__VA_ARGS__); \
			if (hook->mocked()) hook->callMock<void>(frame); }}} while(0)

#define INTERCEPT(name, ret, ...) INTERCEPT_MANUAL(name, ret, nullptr, ##__VA_ARGS__)
#define INTERCEPT_METHOD(name, ret, ...) INTERCEPT_MANUAL(name, ret, this, ##__VA_ARGS__)
#define INTERCEPT_LOG(name, ...) INTERCEPT_LOG_MANUAL(name, nullptr, ##__VA_ARGS__)
#define INTERCEPT_LOG_METHOD(name, ...) INTERCEPT_LOG_MANUAL(name, this, ##__VA_ARGS__)

namespace Intercept {
	typedef unsigned char byte;

	class Hook {
		const char* _file;
		int _line;
		bool _isMethod;
		bool _wasReached;
		std::atomic<bool> _enabled;
		std::atomic<bool> _hasMock;
		std::function<void(const Frame*)> mock;

	public:
		const char* name;

		inline Hook* registerHook(const char* name, bool isMethod, const char* file, int line)
		{
			this->name = name;
			_file = file;
			_line = line;
			_isMethod = isMethod;
			_wasReached = true;
			_enabled = INTERCEPT_CONFIG_ENABLED;
			_hasMock = false;
			std::lock_guard<std::mutex> lock(gRegisterMutex);
			auto result = gHooks.insert(std::make_pair(name, this));
			if (!result.second) {
				Hook* existing = result.first->second;
				if (existing->wasReached()) {
					if (!(existing->_line == line && ::strcmp(existing->_file, file) == 0))
						throw std::logic_error(std::string("already initialized hook for ") + name + " at " + location());

					return existing;
				}

				if (existing->mocked()) {
					mock = std::move(existing->mock);
					_hasMock.store(true, std::memory_order_release);
				}
				result.first->second = this;
				delete existing;
			}
			return this;
		}

		template<class F>
		void setMock(F&& f) {
			if (_hasMock.load(std::memory_order_acquire))
				throw std::logic_error(std::string("cannot set mock if it's already set, use clearMock first if changing it. hook: ") + name);

			// Coerce the damn thing into a std::function<void(void*)>. We'll coerce it back when we call it.
			new (&mock) std::function<decltype(f.operator()(nullptr))(const Frame*)>(f);
			_hasMock.store(true, std::memory_order_release);
		}

		inline void clearMock() {
			_hasMock.store(false, std::memory_order_release);
			memset(&mock, 0, sizeof(mock));
		}

		template<class T>
		T callMock(const Frame* frame) {
			return ((std::function<T(const Frame*)>*)&mock)->operator()(frame);
		}

		inline std::string location() const {
			return _file + (":" + std::to_string(_line));
		}

		inline bool wasReached() const noexcept {
			return _wasReached;
		}

		inline bool isMethod() const noexcept {
			return _isMethod;
		}

		inline bool mocked() const noexcept {
			return _hasMock.load(std::memory_order_acquire);
		}

		inline bool enabled() const noexcept {
			return _enabled.load(std::memory_order_relaxed);
		}

		inline bool enable() noexcept {
			return _enabled.exchange(true);
		}

		inline bool disable() noexcept {
			return _enabled.exchange(false);
		}
	};

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
		Hook& _hook;
		void* _this;
		uint32_t _ctx;
		uint32_t _prev;
		uint16_t _argCount;
		uint16_t _size;
		uint16_t _offsets[];

	public:
		inline Frame(Context& ctx, Hook& hook, void* self, uint32_t prev, uint16_t count) :
			_hook(hook), _this(self), _ctx(uint32_t(uintptr_t(this) - uintptr_t(&ctx))), _prev(prev), _argCount(count), _size(uint16_t(sizeof(Frame)) + count*2) {}

		inline Hook* hook() const {
			return &_hook;
		}

		inline Context& ctx() const {
			return *(Context*)((char*)this - _ctx);
		}

		inline uint32_t totalArgs() const {
			return _argCount;
		}

		const Frame* prev() const;
		inline const Frame* next() const {
			return (Frame*)((char*)this + _size);
		}

		template<class T>
		const T* getThis() const {
			return (T*)_this;
		}

		template<class T>
		const T& get(uint32_t i) const {
			if (i >= _argCount)
				throw std::out_of_range("index to Frame::get<T>() out of range");

			return *(T*)((char*)_offsets + _offsets[i]);
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
		std::unordered_map<const char*,uint32_t,HashCString,EqCString> _called;
		std::vector<const char*> _mocks;
		std::vector<std::function<void(void)> > _dtors;
		uint32_t _count = 0;
		uint32_t pos = 0;
		uint32_t bufSize = INTERCEPT_STACK_BUFFER_SIZE;
		char* buf;
		const Frame* lastFrame;
		char _buf[INTERCEPT_STACK_BUFFER_SIZE];

	public:
		inline static Context* get() noexcept {
			return tlsCtx;
		}

		inline Context() : buf(_buf), lastFrame((Frame*)buf) {
			tlsCtx = this;
		}

		inline ~Context() {
			for (auto& dtor : _dtors) {
				dtor();
			}
			tlsCtx = nullptr;
			if (buf != _buf) {
				delete [] buf;
				buf = nullptr;
			}
			std::lock_guard<std::mutex> lock(gRegisterMutex);
			for (auto hookName : _mocks) {
				auto hook = gHooks[hookName];
				if (!hook->wasReached())
					::fprintf(stderr, "WARNING: hook %s was mocked but never reached!\n", hook->name);

				hook->clearMock();
			}
		}

		Context(const Context&) = delete;
		Context(Context&&) = delete;

		inline void reset() {
			this->~Context();
			new (this) Context();
		}

		inline void clear() {
			for (auto& dtor : _dtors) {
				dtor();
			}
			_dtors.clear();
			_called.clear();
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
			// TODO use dtors to copy the objects that might need to invoke a copy constructor
		}

		template<class F>
		void setMock(const char* name, F&& f) {
			Hook* hook;
			{
				std::lock_guard<std::mutex> lock(gRegisterMutex);
				auto result = gHooks.insert({name,nullptr});
				hook = result.first->second;
				// If there wasn't already a hook by that name, the INTERCEPT hasn't been reached yet.
				// Create a temporary Hook on the heap and attach the mock to that. When the INTERCEPT
				// runs we'll replace it and delete this temporary hook after copying the mock.
				if (result.second) {
					result.first->second = hook = new Hook();
					hook->name = name;
				}
			}

			hook->setMock(f);
			_mocks.push_back(name);
		}

		void clearMock(const char* name) {
			Hook* hook;
			{
				std::lock_guard<std::mutex> lock(gRegisterMutex);
				hook = gHooks[name];
			}
			hook->clearMock();
			_mocks.erase(
				std::remove_if(_mocks.begin(), _mocks.end(), [=](const char* other) { return ::strcmp(name, other) == 0; }),
				_mocks.end()
			);
		}

		Frame* createFrame(Hook& hook, const void* self, size_t numArgs=0) {
			char* dest = buf+pos;
			auto result = _called.insert({hook.name,pos});
			auto hdrSize = uint32_t(sizeof(Frame) + numArgs*2);

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

		const Frame* pushFrame(Hook& hook, const void* self) {
			return createFrame(hook, self);
		}

		template<class... Args>
		const Frame* pushFrame(Hook& hook, const void* self, const Args&... args) {
			auto frame = createFrame(hook, self, sizeof...(Args));
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
			if (!std::is_trivially_destructible<T>::value) {
				// Use buf and pos here, because we might grow buf, meaning dest might not point to the object anymore
				_dtors.emplace_back([self=this,p=pos]() { ((T*)(self->buf + p))->~T(); });
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

	inline const Frame* Frame::prev() const {
		return (_prev == 0) ? nullptr : (Frame*)(ctx().buf + _prev);
	}
}


#ifdef INTERCEPT_CONFIG_MAIN

namespace Intercept {
	thread_local Context* tlsCtx = nullptr;
	std::mutex gRegisterMutex;
	std::unordered_map<const char *, Hook *, HashCString, EqCString> gHooks;
}
#endif

#endif // ifdef INTERCEPT_ENABLED