using System;
using System.IO;

namespace PcapCompressor.Tools
{
    /// <summary>
    /// For read a large Files than 2G in memory, use a Read/Write
    /// </summary>
    public class HugeMemoryStream : Stream
    {
        #region Fields

        private const int PAGE_SIZE = 1024000;
        private const int ALLOC_STEP = 1024;

        private byte[][] _streamBuffers;

        private int _pageCount = 0;
        private long _allocatedBytes = 0;

        private long _position = 0;
        private long _length = 0;

        #endregion Fields

        #region Internals


        public HugeMemoryStream()
        {
            _streamBuffers = new byte[ALLOC_STEP][];
            _pageCount = 0;
            _allocatedBytes = 0;
            _position = 0;
            _length = 0;
        }

        // 带字节数组参数的构造函数
        public HugeMemoryStream(byte[] buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            _length = buffer.Length;
            _position = 0;

            int pageCount = GetPageCount(_length);
            _streamBuffers = new byte[pageCount][];

            for (int i = 0; i < pageCount; i++)
            {
                int currentPageSize = Math.Min(PAGE_SIZE, buffer.Length - (i * PAGE_SIZE));
                _streamBuffers[i] = new byte[currentPageSize];
                Array.Copy(buffer, i * PAGE_SIZE, _streamBuffers[i], 0, currentPageSize);
            }

            _allocatedBytes = _length;
            _pageCount = pageCount;
        }


        /// <summary>
        /// Return Array byte for Small file less than 2Gb
        /// </summary>
        /// <returns>Array byte</returns>
        [Obsolete("Only Work for small file, a large file use ToLongArray or not use Array use Read or Write", false)]
        public byte[] ToArray()
        {
            if (Length <= int.MaxValue)
            {
                long firstposition = Position;
                Position = 0;
                byte[] destination = new byte[Length];
                Read(destination, 0, (int)Length);
                Position = firstposition;
                return destination;
            }
            else
            {
                return _streamBuffers[0];
            }
        }

        /// <summary>
        /// Return matriz Array byte for Big file than 2Gb
        /// </summary>
        /// <returns>Array byte</returns>
        [Obsolete("Not use Array for a lager file, use Read or Write", false)]
        public byte[][] ToLongArray()
        {
            return _streamBuffers;
        }

        private int GetPageCount(long length)
        {
            int pageCount = (int)(length / PAGE_SIZE) + 1;

            if ((length % PAGE_SIZE) == 0)
                pageCount--;

            return pageCount;
        }

        private void ExtendPages()
        {
            if (_streamBuffers == null)
            {
                _streamBuffers = new byte[ALLOC_STEP][];
            }
            else
            {
                byte[][] streamBuffers = new byte[_streamBuffers.Length + ALLOC_STEP][];
                Array.Copy(_streamBuffers, streamBuffers, _streamBuffers.Length);
                _streamBuffers = streamBuffers;
            }

            _pageCount = _streamBuffers.Length;
        }

        private void AllocSpaceIfNeeded(long value)
        {
            if (value < 0)
                throw new InvalidOperationException("AllocSpaceIfNeeded < 0");

            if (value == 0)
                return;

            int currentPageCount = GetPageCount(_allocatedBytes);
            int neededPageCount = GetPageCount(value);

            while (currentPageCount < neededPageCount)
            {
                if (currentPageCount == _pageCount)
                    ExtendPages();

                _streamBuffers[currentPageCount++] = new byte[PAGE_SIZE];
            }

            _allocatedBytes = (long)currentPageCount * PAGE_SIZE;

            value = Math.Max(value, _length);

            if (_position > (_length = value))
                _position = _length;
        }

        #endregion Internals

        #region Stream

        /// <summary>
        /// Can Read Stream
        /// </summary>
        public override bool CanRead => true;

        /// <summary>
        /// Can Seek Stream
        /// </summary>
        public override bool CanSeek => true;

        /// <summary>
        /// Can Write Stream
        /// </summary>
        public override bool CanWrite => true;

        /// <summary>
        /// Length
        /// </summary>
        public override long Length => _length;

        /// <summary>
        /// Position
        /// </summary>
        public override long Position
        {
            get { return _position; }
            set
            {
                if (value > _length)
                    throw new InvalidOperationException("Position > Length");
                else if (value < 0)
                    throw new InvalidOperationException("Position < 0");
                else
                    _position = value;
            }
        }

        /// <summary>
        /// Flush - NotSupportedException
        /// </summary>
        public override void Flush()
        { }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int currentPage = (int)(_position / PAGE_SIZE);
            int currentOffset = (int)(_position % PAGE_SIZE);
            int currentLength = PAGE_SIZE - currentOffset;

            long startPosition = _position;

            if (startPosition + count > _length)
                count = (int)(_length - startPosition);

            while (count != 0 && _position < _length)
            {
                if (currentLength > count)
                    currentLength = count;

                Array.Copy(_streamBuffers[currentPage++], currentOffset, buffer, offset, currentLength);

                offset += currentLength;
                _position += currentLength;
                count -= currentLength;

                currentOffset = 0;
                currentLength = PAGE_SIZE;
            }

            return (int)(_position - startPosition);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            switch (origin)
            {
                case SeekOrigin.Begin:
                    break;

                case SeekOrigin.Current:
                    offset += _position;
                    break;

                case SeekOrigin.End:
                    offset = _length - offset;
                    break;

                default:
                    throw new ArgumentOutOfRangeException("origin");
            }

            return Position = offset;
        }

        public override void SetLength(long value)
        {
            if (value < 0)
                throw new InvalidOperationException("SetLength < 0");

            if (value == 0)
            {
                _streamBuffers = null;
                _allocatedBytes = _position = _length = 0;
                _pageCount = 0;
                return;
            }

            int currentPageCount = GetPageCount(_allocatedBytes);
            int neededPageCount = GetPageCount(value);

            // Removes unused buffers if decreasing stream length
            while (currentPageCount > neededPageCount)
                _streamBuffers[--currentPageCount] = null;

            AllocSpaceIfNeeded(value);

            if (_position > (_length = value))
                _position = _length;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            int currentPage = (int)(_position / PAGE_SIZE);
            int currentOffset = (int)(_position % PAGE_SIZE);
            int currentLength = PAGE_SIZE - currentOffset;

            AllocSpaceIfNeeded(_position + count);

            while (count != 0)
            {
                if (currentLength > count)
                    currentLength = count;

                Array.Copy(buffer, offset, _streamBuffers[currentPage++], currentOffset, currentLength);

                offset += currentLength;
                _position += currentLength;
                count -= currentLength;

                currentOffset = 0;
                currentLength = PAGE_SIZE;
            }
        }

        #endregion Stream

        #region IDispose

        protected override void Dispose(bool disposing)
        {
            _streamBuffers = null;
            _pageCount = 0;
            _allocatedBytes = 0;
            _position = 0;
            _length = 0;
            base.Dispose(disposing);
        }

        #endregion IDispose
    }
}