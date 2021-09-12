#ifndef TRANSPORT_H
#define TRANSPORT_H

namespace WIC {

    class Transport {

    public:

        Transport();
        virtual ~Transport();

        virtual void close();
    };



};

#endif
